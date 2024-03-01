use jni::objects::JByteBuffer;
use jni::objects::JString;
use jni::objects::JValue;
use jni::sys::jboolean;
use jni::JNIEnv;
use jni::{
    objects::{GlobalRef, JClass, JObject},
    JavaVM,
};

use jni::errors::{Error as JniError, Result as JniResult};
use lazy_static::lazy_static;
use std::ops::Not;
use std::sync::atomic::{AtomicPtr, Ordering::SeqCst};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};
lazy_static! {
    static ref JVM: RwLock<Option<JavaVM>> = RwLock::new(None);
    static ref MAIN_SERVICE_CTX: RwLock<Option<GlobalRef>> = RwLock::new(None); // MainService -> video service / audio service / info
    static ref VIDEO_RAW: Mutex<FrameRaw> = Mutex::new(FrameRaw::new("video", MAX_VIDEO_FRAME_TIMEOUT));
    static ref AUDIO_RAW: Mutex<FrameRaw> = Mutex::new(FrameRaw::new("audio", MAX_AUDIO_FRAME_TIMEOUT));
    static ref NDK_CONTEXT_INITED: Mutex<bool> = Default::default();
}

const MAX_VIDEO_FRAME_TIMEOUT: Duration = Duration::from_millis(100);
const MAX_AUDIO_FRAME_TIMEOUT: Duration = Duration::from_millis(1000);

struct FrameRaw {
    name: &'static str,
    ptr: AtomicPtr<u8>,
    len: usize,
    last_update: Instant,
    timeout: Duration,
    enable: bool,
}

impl FrameRaw {
    fn new(name: &'static str, timeout: Duration) -> Self {
        FrameRaw {
            name,
            ptr: AtomicPtr::default(),
            len: 0,
            last_update: Instant::now(),
            timeout,
            enable: false,
        }
    }

    fn set_enable(&mut self, value: bool) {
        self.enable = value;
    }

    fn update(&mut self, data: *mut u8, len: usize) {
        if self.enable.not() {
            return;
        }
        self.len = len;
        self.ptr.store(data, SeqCst);
        self.last_update = Instant::now();
    }

    // take inner data as slice
    // release when success
    fn take<'a>(&mut self) -> Option<&'a [u8]> {
        if self.enable.not() {
            return None;
        }
        let ptr = self.ptr.load(SeqCst);
        if ptr.is_null() || self.len == 0 {
            None
        } else {
            if self.last_update.elapsed() > self.timeout {
                log::trace!("Failed to take {} raw,timeout!", self.name);
                return None;
            }
            let slice = unsafe { std::slice::from_raw_parts(ptr, self.len) };
            self.release();
            Some(slice)
        }
    }

    fn release(&mut self) {
        self.len = 0;
        self.ptr.store(std::ptr::null_mut(), SeqCst);
    }
}

pub fn get_video_raw<'a>() -> Option<&'a [u8]> {
    VIDEO_RAW.lock().ok()?.take()
}

pub fn get_audio_raw<'a>() -> Option<&'a [u8]> {
    AUDIO_RAW.lock().ok()?.take()
}

#[no_mangle]
pub extern "system" fn Java_com_carriez_flutter_1hbb_MainService_onVideoFrameUpdate(
    env: JNIEnv,
    _class: JClass,
    buffer: JObject,
) {
    let jb = JByteBuffer::from(buffer);
    if let Ok(data) = env.get_direct_buffer_address(&jb) {
        if let Ok(len) = env.get_direct_buffer_capacity(&jb) {
            VIDEO_RAW.lock().unwrap().update(data, len);
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_carriez_flutter_1hbb_MainService_onAudioFrameUpdate(
    env: JNIEnv,
    _class: JClass,
    buffer: JObject,
) {
    let jb = JByteBuffer::from(buffer);
    if let Ok(data) = env.get_direct_buffer_address(&jb) {
        if let Ok(len) = env.get_direct_buffer_capacity(&jb) {
            AUDIO_RAW.lock().unwrap().update(data, len);
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_carriez_flutter_1hbb_MainService_setFrameRawEnable(
    env: JNIEnv,
    _class: JClass,
    name: JString,
    value: jboolean,
) {
    let mut env = env;
    if let Ok(name) = env.get_string(&name) {
        let name: String = name.into();
        let value = value.eq(&1);
        if name.eq("video") {
            VIDEO_RAW.lock().unwrap().set_enable(value);
        } else if name.eq("audio") {
            AUDIO_RAW.lock().unwrap().set_enable(value);
        }
    };
}

#[no_mangle]
pub extern "system" fn Java_com_carriez_flutter_1hbb_MainService_init(
    env: JNIEnv,
    _class: JClass,
    ctx: JObject,
) {
    log::debug!("MainService init from java");
    if let Ok(jvm) = env.get_java_vm() {
        *JVM.write().unwrap() = Some(jvm);
        if let Ok(context) = env.new_global_ref(ctx) {
            *MAIN_SERVICE_CTX.write().unwrap() = Some(context);
            init_ndk_context().ok();
        }
    }
}

pub fn call_main_service_pointer_input(kind: &str, mask: i32, x: i32, y: i32) -> JniResult<()> {
    if let (Some(jvm), Some(ctx)) = (
        JVM.read().unwrap().as_ref(),
        MAIN_SERVICE_CTX.read().unwrap().as_ref(),
    ) {
        let mut env = jvm.attach_current_thread_as_daemon()?;
        let kind = env.new_string(kind)?;
        env.call_method(
            ctx,
            "rustPointerInput",
            "(Ljava/lang/String;III)V",
            &[
                JValue::Object(&JObject::from(kind)),
                JValue::Int(mask),
                JValue::Int(x),
                JValue::Int(y),
            ],
        )?;
        return Ok(());
    } else {
        return Err(JniError::ThrowFailed(-1));
    }
}

pub fn call_main_service_key_event(data: &[u8]) -> JniResult<()> {
    if let (Some(jvm), Some(ctx)) = (
        JVM.read().unwrap().as_ref(),
        MAIN_SERVICE_CTX.read().unwrap().as_ref(),
    ) {
        let mut env = jvm.attach_current_thread_as_daemon()?;
        let data = env.byte_array_from_slice(data)?;

        env.call_method(
            ctx,
            "rustKeyEventInput",
            "([B)V",
            &[JValue::Object(&JObject::from(data))],
        )?;
        return Ok(());
    } else {
        return Err(JniError::ThrowFailed(-1));
    }
}

pub fn call_main_service_set_clip_text(name: &str) -> JniResult<()> {
    if let (Some(jvm), Some(ctx)) = (
        JVM.read().unwrap().as_ref(),
        MAIN_SERVICE_CTX.read().unwrap().as_ref(),
    ) {
        let mut env = jvm.attach_current_thread_as_daemon()?;
        let name = env.new_string(name)?;
        env.call_method(
            ctx,
            "rustSetClipText",
            "(Ljava/lang/String;)V",
            &[JValue::Object(&JObject::from(name))],
        )?;
        return Ok(());
    }
    else {
        return Err(JniError::ThrowFailed(-1));
    }
}

pub fn call_main_service_get_by_name(name: &str) -> JniResult<String> {
    if let (Some(jvm), Some(ctx)) = (
        JVM.read().unwrap().as_ref(),
        MAIN_SERVICE_CTX.read().unwrap().as_ref(),
    ) {
        let mut env = jvm.attach_current_thread_as_daemon()?;
        let name = env.new_string(name)?;
        let res = env
            .call_method(
                ctx,
                "rustGetByName",
                "(Ljava/lang/String;)Ljava/lang/String;",
                &[JValue::Object(&JObject::from(name))],
            )?
            .l()?;
        let res = JString::from(res);
        let res = env.get_string(&res)?;
        let res = res.to_string_lossy().to_string();
        return Ok(res);
    } else {
        return Err(JniError::ThrowFailed(-1));
    }
}

pub fn call_main_service_set_by_name(
    name: &str,
    arg1: Option<&str>,
    arg2: Option<&str>,
) -> JniResult<()> {
    if let (Some(jvm), Some(ctx)) = (
        JVM.read().unwrap().as_ref(),
        MAIN_SERVICE_CTX.read().unwrap().as_ref(),
    ) {
        let mut env = jvm.attach_current_thread_as_daemon()?;
        let name = env.new_string(name)?;
        let arg1 = env.new_string(arg1.unwrap_or(""))?;
        let arg2 = env.new_string(arg2.unwrap_or(""))?;

        env.call_method(
            ctx,
            "rustSetByName",
            "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
            &[
                JValue::Object(&JObject::from(name)),
                JValue::Object(&JObject::from(arg1)),
                JValue::Object(&JObject::from(arg2)),
            ],
        )?;
        return Ok(());
    } else {
        return Err(JniError::ThrowFailed(-1));
    }
}

fn init_ndk_context() -> JniResult<()> {
    let mut lock = NDK_CONTEXT_INITED.lock().unwrap();
    if *lock {
        unsafe {
            ndk_context::release_android_context();
        }
        *lock = false;
    }
    if let (Some(jvm), Some(ctx)) = (
        JVM.read().unwrap().as_ref(),
        MAIN_SERVICE_CTX.read().unwrap().as_ref(),
    ) {
        unsafe {
            ndk_context::initialize_android_context(
                jvm.get_java_vm_pointer() as _,
                ctx.as_obj().as_raw() as _,
            );
        }
        *lock = true;
        return Ok(());
    }
    Err(JniError::ThrowFailed(-1))
}

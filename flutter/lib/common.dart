import 'dart:async';
import 'dart:convert';
import 'dart:ffi' hide Size;
import 'dart:io';
import 'dart:math';

import 'package:back_button_interceptor/back_button_interceptor.dart';
import 'package:desktop_multi_window/desktop_multi_window.dart';
import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common/formatter/id_formatter.dart';
import 'package:flutter_hbb/desktop/widgets/refresh_wrapper.dart';
import 'package:flutter_hbb/desktop/widgets/tabbar_widget.dart';
import 'package:flutter_hbb/main.dart';
import 'package:flutter_hbb/models/desktop_render_texture.dart';
import 'package:flutter_hbb/models/peer_model.dart';
import 'package:flutter_hbb/models/state_model.dart';
import 'package:flutter_hbb/utils/multi_window_manager.dart';
import 'package:flutter_hbb/utils/platform_channel.dart';
import 'package:flutter_svg/flutter_svg.dart';
import 'package:get/get.dart';
import 'package:uni_links/uni_links.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:uuid/uuid.dart';
import 'package:win32/win32.dart' as win32;
import 'package:window_manager/window_manager.dart';
import 'package:window_size/window_size.dart' as window_size;

import '../consts.dart';
import 'common/widgets/overlay.dart';
import 'mobile/pages/file_manager_page.dart';
import 'mobile/pages/remote_page.dart';
import 'models/input_model.dart';
import 'models/model.dart';
import 'models/platform_model.dart';

final globalKey = GlobalKey<NavigatorState>();
final navigationBarKey = GlobalKey();

final isAndroid = Platform.isAndroid;
final isIOS = Platform.isIOS;
final isDesktop = Platform.isWindows || Platform.isMacOS || Platform.isLinux;
var isWeb = false;
var isWebDesktop = false;
var isMobile = isAndroid || isIOS;
var version = "";
int androidVersion = 0;

/// only available for Windows target
int windowsBuildNumber = 0;
DesktopType? desktopType;

bool get isMainDesktopWindow =>
    desktopType == DesktopType.main || desktopType == DesktopType.cm;

/// Check if the app is running with single view mode.
bool isSingleViewApp() {
  return desktopType == DesktopType.cm;
}

/// * debug or test only, DO NOT enable in release build
bool isTest = false;

typedef F = String Function(String);
typedef FMethod = String Function(String, dynamic);

typedef StreamEventHandler = Future<void> Function(Map<String, dynamic>);
typedef SessionID = UuidValue;
final iconHardDrive = MemoryImage(Uint8List.fromList(base64Decode(
    'iVBORw0KGgoAAAANSUhEUgAAAMgAAADICAMAAACahl6sAAAAmVBMVEUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAjHWqVAAAAMnRSTlMAv0BmzLJNXlhiUu2fxXDgu7WuSUUe29LJvpqUjX53VTstD7ilNujCqTEk5IYH+vEoFjKvAagAAAPpSURBVHja7d0JbhpBEIXhB3jYzb5vBgzYgO04df/DJXGUKMwU9ECmZ6pQfSfw028LCXW3YYwxxhhjjDHGGGOM0eZ9VV1MckdKWLM1bRQ/35GW/WxHHu1me6ShuyHvNl34VhlTKsYVeDWj1EzgUZ1S1DrAk/UDparZgxd9Sl0BHnxSBhpI3jfKQG2FpLUpE69I2ILikv1nsvygjBwPSNKYMlNHggqUoSKS80AZCnwHqQ1zCRvW+CRegwRFeFAMKKrtM8gTPJlzSfwFgT9dJom3IDN4VGaSeAryAK8m0SSeghTg1ZYiql6CjBDhO8mzlyAVhKhIwgXxrh5NojGIhyRckEdwpCdhgpSQgiWTRGMQNonGIGySp0SDvMDBX5KWxiB8Eo1BgE00SYJBykhNnkmSWJAcLpGaJNMgfJKyxiDAK4WNEwryhMtkJsk8CJtEYxA+icYgQIfCcgkEqcJNXhIRQdgkGoPwSTQG+e8khdu/7JOVREwQIKCwF41B2CQljUH4JLcH6SI+OUlEBQHa0SQag/BJNAbhkjxqDMIn0RgEeI4muSlID9eSkERgEKAVTaIxCJ9EYxA2ydVB8hCASVLRGAQYR5NoDMIn0RgEyFHYSGMQPonGII4kziCNvBgNJonEk4u3GAk8Sprk6eYaqbMDY0oKvUm5jfC/viGiSypV7+M3i2iDsAGpNEDYjlTa3W8RdR/r544g50ilnA0RxoZIE2NIXqQbhkAkGyKNDZHGhkhjQ6SxIdLYEGlsiDQ2JGTVeD0264U9zipPh7XOooffpA6pfNCXjxl4/c3pUzlChwzor53zwYYVfpI5pOV6LWFF/2jiJ5FDSs5jdY/0rwUAkUMeXWdBqnSqD0DikBqdqCHsjTvELm9In0IOri/0pwAEDtlSyNaRjAIAAoesKWTtuusxByBwCJp0oomwBXcYUuCQgE50ENajE4OvZAKHLB1/68Br5NqiyCGYOY8YRd77kTkEb64n7lZN+mOIX4QOwb5FX0ZVx3uOxwW+SB0CbBubemWP8/rlaaeRX+M3uUOuZENsiA25zIbYkPsZElBIHwL13U/PTjJ/cyOOEoVM3I+hziDQlELm7pPxw3eI8/7gPh1fpLA6xGnEeDDgO0UcIAzzM35HxLPIq5SXe9BLzOsj9eUaQqyXzxS1QFSfWM2cCANiHcAISJ0AnCKpUwTuIkkA3EeSInAXSQKcs1V18e24wlllUmQp9v9zXKeHi+akRAMOPVKhAqdPBZeUmnnEsO6QcJ0+4qmOSbBxFfGVRiTUqITrdKcCbyYO3/K4wX4+aQ+FfNjXhu3JfAVjjDHGGGOMMcYYY4xIPwCgfqT6TbhCLAAAAABJRU5ErkJggg==')));

enum DesktopType {
  main,
  remote,
  fileTransfer,
  cm,
  portForward,
}

class IconFont {
  static const _family1 = 'Tabbar';
  static const _family2 = 'PeerSearchbar';
  IconFont._();

  static const IconData max = IconData(0xe606, fontFamily: _family1);
  static const IconData restore = IconData(0xe607, fontFamily: _family1);
  static const IconData close = IconData(0xe668, fontFamily: _family1);
  static const IconData min = IconData(0xe609, fontFamily: _family1);
  static const IconData add = IconData(0xe664, fontFamily: _family1);
  static const IconData menu = IconData(0xe628, fontFamily: _family1);
  static const IconData search = IconData(0xe6a4, fontFamily: _family2);
  static const IconData roundClose = IconData(0xe6ed, fontFamily: _family2);
  static const IconData addressBook =
      IconData(0xe602, fontFamily: "AddressBook");
}

class ColorThemeExtension extends ThemeExtension<ColorThemeExtension> {
  const ColorThemeExtension({
    required this.border,
    required this.border2,
    required this.highlight,
    required this.drag_indicator,
    required this.shadow,
    required this.errorBannerBg,
    required this.me,
  });

  final Color? border;
  final Color? border2;
  final Color? highlight;
  final Color? drag_indicator;
  final Color? shadow;
  final Color? errorBannerBg;
  final Color? me;

  static final light = ColorThemeExtension(
    border: Color(0xFFCCCCCC),
    border2: Color(0xFFBBBBBB),
    highlight: Color(0xFFE5E5E5),
    drag_indicator: Colors.grey[800],
    shadow: Colors.black,
    errorBannerBg: Color(0xFFFDEEEB),
    me: Colors.green,
  );

  static final dark = ColorThemeExtension(
    border: Color(0xFF555555),
    border2: Color(0xFFE5E5E5),
    highlight: Color(0xFF3F3F3F),
    drag_indicator: Colors.grey,
    shadow: Colors.grey,
    errorBannerBg: Color(0xFF470F2D),
    me: Colors.greenAccent,
  );

  @override
  ThemeExtension<ColorThemeExtension> copyWith({
    Color? border,
    Color? border2,
    Color? highlight,
    Color? drag_indicator,
    Color? shadow,
    Color? errorBannerBg,
    Color? me,
  }) {
    return ColorThemeExtension(
      border: border ?? this.border,
      border2: border2 ?? this.border2,
      highlight: highlight ?? this.highlight,
      drag_indicator: drag_indicator ?? this.drag_indicator,
      shadow: shadow ?? this.shadow,
      errorBannerBg: errorBannerBg ?? this.errorBannerBg,
      me: me ?? this.me,
    );
  }

  @override
  ThemeExtension<ColorThemeExtension> lerp(
      ThemeExtension<ColorThemeExtension>? other, double t) {
    if (other is! ColorThemeExtension) {
      return this;
    }
    return ColorThemeExtension(
      border: Color.lerp(border, other.border, t),
      border2: Color.lerp(border2, other.border2, t),
      highlight: Color.lerp(highlight, other.highlight, t),
      drag_indicator: Color.lerp(drag_indicator, other.drag_indicator, t),
      shadow: Color.lerp(shadow, other.shadow, t),
      errorBannerBg: Color.lerp(shadow, other.errorBannerBg, t),
      me: Color.lerp(shadow, other.me, t),
    );
  }
}

class MyTheme {
  MyTheme._();

  static const Color grayBg = Color(0xFFEFEFF2);
  static const Color accent = Color(0xFF0071FF);
  static const Color accent50 = Color(0x770071FF);
  static const Color accent80 = Color(0xAA0071FF);
  static const Color canvasColor = Color(0xFF212121);
  static const Color border = Color(0xFFCCCCCC);
  static const Color idColor = Color(0xFF00B6F0);
  static const Color darkGray = Color.fromARGB(255, 148, 148, 148);
  static const Color cmIdColor = Color(0xFF21790B);
  static const Color dark = Colors.black87;
  static const Color button = Color(0xFF2C8CFF);
  static const Color hoverBorder = Color(0xFF999999);
  static const Color bordDark = Colors.white24;
  static const Color bordLight = Colors.black26;
  static const Color dividerDark = Colors.white38;
  static const Color dividerLight = Colors.black38;

  // ListTile
  static const ListTileThemeData listTileTheme = ListTileThemeData(
    shape: RoundedRectangleBorder(
      borderRadius: BorderRadius.all(
        Radius.circular(5),
      ),
    ),
  );

  static SwitchThemeData switchTheme() {
    return SwitchThemeData(splashRadius: isDesktop ? 0 : kRadialReactionRadius);
  }

  static RadioThemeData radioTheme() {
    return RadioThemeData(splashRadius: isDesktop ? 0 : kRadialReactionRadius);
  }

  // Checkbox
  static const CheckboxThemeData checkboxTheme = CheckboxThemeData(
    splashRadius: 0,
    shape: RoundedRectangleBorder(
      borderRadius: BorderRadius.all(
        Radius.circular(5),
      ),
    ),
  );

  // TextButton
  // Value is used to calculate "dialog.actionsPadding"
  static const double mobileTextButtonPaddingLR = 20;

  // TextButton on mobile needs a fixed padding, otherwise small buttons
  // like "OK" has a larger left/right padding.
  static TextButtonThemeData mobileTextButtonTheme = TextButtonThemeData(
    style: TextButton.styleFrom(
      padding: EdgeInsets.symmetric(horizontal: mobileTextButtonPaddingLR),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(8.0),
      ),
    ),
  );

  //tooltip
  static TooltipThemeData tooltipTheme() {
    return TooltipThemeData(
      waitDuration: Duration(seconds: 1, milliseconds: 500),
    );
  }

  // Dialogs
  static const double dialogPadding = 24;

  // padding bottom depends on content (some dialogs has no content)
  static EdgeInsets dialogTitlePadding({bool content = true}) {
    final double p = dialogPadding;

    return EdgeInsets.fromLTRB(p, p, p, content ? 0 : p);
  }

  // padding bottom depends on actions (mobile has dialogs without actions)
  static EdgeInsets dialogContentPadding({bool actions = true}) {
    final double p = dialogPadding;

    return isDesktop
        ? EdgeInsets.fromLTRB(p, p, p, actions ? (p - 4) : p)
        : EdgeInsets.fromLTRB(p, p, p, actions ? (p / 2) : p);
  }

  static EdgeInsets dialogActionsPadding() {
    final double p = dialogPadding;

    return isDesktop
        ? EdgeInsets.fromLTRB(p, 0, p, (p - 4))
        : EdgeInsets.fromLTRB(p, 0, (p - mobileTextButtonPaddingLR), (p / 2));
  }

  static EdgeInsets dialogButtonPadding = isDesktop
      ? EdgeInsets.only(left: dialogPadding)
      : EdgeInsets.only(left: dialogPadding / 3);

  static ScrollbarThemeData scrollbarTheme = ScrollbarThemeData(
    thickness: MaterialStateProperty.all(6),
    thumbColor: MaterialStateProperty.resolveWith<Color?>((states) {
      if (states.contains(MaterialState.dragged)) {
        return Colors.grey[900];
      } else if (states.contains(MaterialState.hovered)) {
        return Colors.grey[700];
      } else {
        return Colors.grey[500];
      }
    }),
    crossAxisMargin: 4,
  );

  static ScrollbarThemeData scrollbarThemeDark = scrollbarTheme.copyWith(
    thumbColor: MaterialStateProperty.resolveWith<Color?>((states) {
      if (states.contains(MaterialState.dragged)) {
        return Colors.grey[100];
      } else if (states.contains(MaterialState.hovered)) {
        return Colors.grey[300];
      } else {
        return Colors.grey[500];
      }
    }),
  );

  static ThemeData lightTheme = ThemeData(
    brightness: Brightness.light,
    hoverColor: Color.fromARGB(255, 224, 224, 224),
    scaffoldBackgroundColor: Colors.white,
    dialogBackgroundColor: Colors.white,
    dialogTheme: DialogTheme(
      elevation: 15,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(18.0),
        side: BorderSide(
          width: 1,
          color: grayBg,
        ),
      ),
    ),
    scrollbarTheme: scrollbarTheme,
    inputDecorationTheme: isDesktop
        ? InputDecorationTheme(
            fillColor: grayBg,
            filled: true,
            isDense: true,
            border: OutlineInputBorder(
              borderRadius: BorderRadius.circular(8),
            ),
          )
        : null,
    textTheme: const TextTheme(
        titleLarge: TextStyle(fontSize: 19, color: Colors.black87),
        titleSmall: TextStyle(fontSize: 14, color: Colors.black87),
        bodySmall: TextStyle(fontSize: 12, color: Colors.black87, height: 1.25),
        bodyMedium:
            TextStyle(fontSize: 14, color: Colors.black87, height: 1.25),
        labelLarge: TextStyle(fontSize: 16.0, color: MyTheme.accent80)),
    cardColor: grayBg,
    hintColor: Color(0xFFAAAAAA),
    visualDensity: VisualDensity.adaptivePlatformDensity,
    tabBarTheme: const TabBarTheme(
      labelColor: Colors.black87,
    ),
    tooltipTheme: tooltipTheme(),
    splashColor: isDesktop ? Colors.transparent : null,
    highlightColor: isDesktop ? Colors.transparent : null,
    splashFactory: isDesktop ? NoSplash.splashFactory : null,
    textButtonTheme: isDesktop
        ? TextButtonThemeData(
            style: TextButton.styleFrom(
              splashFactory: NoSplash.splashFactory,
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(18.0),
              ),
            ),
          )
        : mobileTextButtonTheme,
    elevatedButtonTheme: ElevatedButtonThemeData(
      style: ElevatedButton.styleFrom(
        backgroundColor: MyTheme.accent,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(8.0),
        ),
      ),
    ),
    outlinedButtonTheme: OutlinedButtonThemeData(
      style: OutlinedButton.styleFrom(
        backgroundColor: grayBg,
        foregroundColor: Colors.black87,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(8.0),
        ),
      ),
    ),
    switchTheme: switchTheme(),
    radioTheme: radioTheme(),
    checkboxTheme: checkboxTheme,
    listTileTheme: listTileTheme,
    menuBarTheme: MenuBarThemeData(
        style:
            MenuStyle(backgroundColor: MaterialStatePropertyAll(Colors.white))),
    colorScheme: ColorScheme.light(
        primary: Colors.blue, secondary: accent, background: grayBg),
  ).copyWith(
    extensions: <ThemeExtension<dynamic>>[
      ColorThemeExtension.light,
      TabbarTheme.light,
    ],
  );
  static ThemeData darkTheme = ThemeData(
    brightness: Brightness.dark,
    hoverColor: Color.fromARGB(255, 45, 46, 53),
    scaffoldBackgroundColor: Color(0xFF18191E),
    dialogBackgroundColor: Color(0xFF18191E),
    dialogTheme: DialogTheme(
      elevation: 15,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(18.0),
        side: BorderSide(
          width: 1,
          color: Color(0xFF24252B),
        ),
      ),
    ),
    scrollbarTheme: scrollbarThemeDark,
    inputDecorationTheme: isDesktop
        ? InputDecorationTheme(
            fillColor: Color(0xFF24252B),
            filled: true,
            isDense: true,
            border: OutlineInputBorder(
              borderRadius: BorderRadius.circular(8),
            ),
          )
        : null,
    textTheme: const TextTheme(
      titleLarge: TextStyle(fontSize: 19),
      titleSmall: TextStyle(fontSize: 14),
      bodySmall: TextStyle(fontSize: 12, height: 1.25),
      bodyMedium: TextStyle(fontSize: 14, height: 1.25),
      labelLarge: TextStyle(
        fontSize: 16.0,
        fontWeight: FontWeight.bold,
        color: accent80,
      ),
    ),
    cardColor: Color(0xFF24252B),
    visualDensity: VisualDensity.adaptivePlatformDensity,
    tabBarTheme: const TabBarTheme(
      labelColor: Colors.white70,
    ),
    tooltipTheme: tooltipTheme(),
    splashColor: isDesktop ? Colors.transparent : null,
    highlightColor: isDesktop ? Colors.transparent : null,
    splashFactory: isDesktop ? NoSplash.splashFactory : null,
    textButtonTheme: isDesktop
        ? TextButtonThemeData(
            style: TextButton.styleFrom(
              splashFactory: NoSplash.splashFactory,
              disabledForegroundColor: Colors.white70,
              foregroundColor: Colors.white70,
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(18.0),
              ),
            ),
          )
        : mobileTextButtonTheme,
    elevatedButtonTheme: ElevatedButtonThemeData(
      style: ElevatedButton.styleFrom(
        backgroundColor: MyTheme.accent,
        foregroundColor: Colors.white,
        disabledForegroundColor: Colors.white70,
        disabledBackgroundColor: Colors.white10,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(8.0),
        ),
      ),
    ),
    outlinedButtonTheme: OutlinedButtonThemeData(
      style: OutlinedButton.styleFrom(
        backgroundColor: Color(0xFF24252B),
        side: BorderSide(color: Colors.white12, width: 0.5),
        disabledForegroundColor: Colors.white70,
        foregroundColor: Colors.white70,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(8.0),
        ),
      ),
    ),
    switchTheme: switchTheme(),
    radioTheme: radioTheme(),
    checkboxTheme: checkboxTheme,
    listTileTheme: listTileTheme,
    menuBarTheme: MenuBarThemeData(
        style: MenuStyle(
            backgroundColor: MaterialStatePropertyAll(Color(0xFF121212)))),
    colorScheme: ColorScheme.dark(
      primary: Colors.blue,
      secondary: accent,
      background: Color(0xFF24252B),
    ),
  ).copyWith(
    extensions: <ThemeExtension<dynamic>>[
      ColorThemeExtension.dark,
      TabbarTheme.dark,
    ],
  );

  static ThemeMode getThemeModePreference() {
    return themeModeFromString(bind.mainGetLocalOption(key: kCommConfKeyTheme));
  }

  static void changeDarkMode(ThemeMode mode) async {
    Get.changeThemeMode(mode);
    if (desktopType == DesktopType.main || isAndroid || isIOS) {
      if (mode == ThemeMode.system) {
        await bind.mainSetLocalOption(key: kCommConfKeyTheme, value: '');
      } else {
        await bind.mainSetLocalOption(
            key: kCommConfKeyTheme, value: mode.toShortString());
      }
      await bind.mainChangeTheme(dark: mode.toShortString());
      // Synchronize the window theme of the system.
      updateSystemWindowTheme();
    }
  }

  static ThemeMode currentThemeMode() {
    final preference = getThemeModePreference();
    if (preference == ThemeMode.system) {
      if (WidgetsBinding.instance.platformDispatcher.platformBrightness ==
          Brightness.light) {
        return ThemeMode.light;
      } else {
        return ThemeMode.dark;
      }
    } else {
      return preference;
    }
  }

  static ColorThemeExtension color(BuildContext context) {
    return Theme.of(context).extension<ColorThemeExtension>()!;
  }

  static TabbarTheme tabbar(BuildContext context) {
    return Theme.of(context).extension<TabbarTheme>()!;
  }

  static ThemeMode themeModeFromString(String v) {
    switch (v) {
      case "light":
        return ThemeMode.light;
      case "dark":
        return ThemeMode.dark;
      default:
        return ThemeMode.system;
    }
  }
}

extension ParseToString on ThemeMode {
  String toShortString() {
    return toString().split('.').last;
  }
}

final ButtonStyle flatButtonStyle = TextButton.styleFrom(
  minimumSize: Size(0, 36),
  padding: EdgeInsets.symmetric(horizontal: 16.0, vertical: 10.0),
  shape: const RoundedRectangleBorder(
    borderRadius: BorderRadius.all(Radius.circular(2.0)),
  ),
);

List<Locale> supportedLocales = const [
  Locale('en', 'US'),
  Locale('zh', 'CN'),
  Locale('zh', 'TW'),
  Locale('zh', 'SG'),
  Locale('fr'),
  Locale('de'),
  Locale('it'),
  Locale('ja'),
  Locale('cs'),
  Locale('pl'),
  Locale('ko'),
  Locale('hu'),
  Locale('pt'),
  Locale('ru'),
  Locale('sk'),
  Locale('id'),
  Locale('da'),
  Locale('eo'),
  Locale('tr'),
  Locale('vi'),
  Locale('pl'),
  Locale('kz'),
  Locale('es'),
];

String formatDurationToTime(Duration duration) {
  var totalTime = duration.inSeconds;
  final secs = totalTime % 60;
  totalTime = (totalTime - secs) ~/ 60;
  final mins = totalTime % 60;
  totalTime = (totalTime - mins) ~/ 60;
  return "${totalTime.toString().padLeft(2, "0")}:${mins.toString().padLeft(2, "0")}:${secs.toString().padLeft(2, "0")}";
}

closeConnection({String? id}) {
  if (isAndroid || isIOS) {
    gFFI.chatModel.hideChatOverlay();
    Navigator.popUntil(globalKey.currentContext!, ModalRoute.withName("/"));
  } else {
    final controller = Get.find<DesktopTabController>();
    controller.closeBy(id);
  }
}

Future<void> windowOnTop(int? id) async {
  if (!isDesktop) {
    return;
  }
  print("Bring window '$id' on top");
  if (id == null) {
    // main window
    if (stateGlobal.isMinimized) {
      await windowManager.restore();
    }
    await windowManager.show();
    await windowManager.focus();
    await rustDeskWinManager.registerActiveWindow(kWindowMainId);
  } else {
    WindowController.fromWindowId(id)
      ..focus()
      ..show();
    rustDeskWinManager.call(WindowType.Main, kWindowEventShow, {"id": id});
  }
}

typedef DialogBuilder = CustomAlertDialog Function(
    StateSetter setState, void Function([dynamic]) close, BuildContext context);

class Dialog<T> {
  OverlayEntry? entry;
  Completer<T?> completer = Completer<T?>();

  Dialog();

  void complete(T? res) {
    try {
      if (!completer.isCompleted) {
        completer.complete(res);
      }
    } catch (e) {
      debugPrint("Dialog complete catch error: $e");
    } finally {
      entry?.remove();
    }
  }
}

class OverlayKeyState {
  final _overlayKey = GlobalKey<OverlayState>();

  /// use global overlay by default
  OverlayState? get state =>
      _overlayKey.currentState ?? globalKey.currentState?.overlay;

  GlobalKey<OverlayState>? get key => _overlayKey;
}

class OverlayDialogManager {
  final Map<String, Dialog> _dialogs = {};
  var _overlayKeyState = OverlayKeyState();
  int _tagCount = 0;

  OverlayEntry? _mobileActionsOverlayEntry;
  RxBool mobileActionsOverlayVisible = false.obs;

  void setOverlayState(OverlayKeyState overlayKeyState) {
    _overlayKeyState = overlayKeyState;
  }

  void dismissAll() {
    _dialogs.forEach((key, value) {
      value.complete(null);
      BackButtonInterceptor.removeByName(key);
    });
    _dialogs.clear();
  }

  void dismissByTag(String tag) {
    _dialogs[tag]?.complete(null);
    _dialogs.remove(tag);
    BackButtonInterceptor.removeByName(tag);
  }

  Future<T?> show<T>(DialogBuilder builder,
      {bool clickMaskDismiss = false,
      bool backDismiss = false,
      String? tag,
      bool useAnimation = true,
      bool forceGlobal = false}) {
    final overlayState =
        forceGlobal ? globalKey.currentState?.overlay : _overlayKeyState.state;

    if (overlayState == null) {
      return Future.error(
          "[OverlayDialogManager] Failed to show dialog, _overlayState is null, call [setOverlayState] first");
    }

    final String dialogTag;
    if (tag != null) {
      dialogTag = tag;
    } else {
      dialogTag = _tagCount.toString();
      _tagCount++;
    }

    final dialog = Dialog<T>();
    _dialogs[dialogTag] = dialog;

    close([res]) {
      _dialogs.remove(dialogTag);
      dialog.complete(res);
      BackButtonInterceptor.removeByName(dialogTag);
    }

    dialog.entry = OverlayEntry(builder: (context) {
      bool innerClicked = false;
      return Listener(
          onPointerUp: (_) {
            if (!innerClicked && clickMaskDismiss) {
              close();
            }
            innerClicked = false;
          },
          child: Container(
              color: Theme.of(context).brightness == Brightness.light
                  ? Colors.black12
                  : Colors.black45,
              child: StatefulBuilder(builder: (context, setState) {
                return Listener(
                  onPointerUp: (_) => innerClicked = true,
                  child: builder(setState, close, overlayState.context),
                );
              })));
    });
    overlayState.insert(dialog.entry!);
    BackButtonInterceptor.add((stopDefaultButtonEvent, routeInfo) {
      if (backDismiss) {
        close();
      }
      return true;
    }, name: dialogTag);
    return dialog.completer.future;
  }

  String showLoading(String text,
      {bool clickMaskDismiss = false,
      bool showCancel = true,
      VoidCallback? onCancel,
      String? tag}) {
    if (tag == null) {
      tag = _tagCount.toString();
      _tagCount++;
    }
    show((setState, close, context) {
      cancel() {
        dismissAll();
        if (onCancel != null) {
          onCancel();
        }
      }

      return CustomAlertDialog(
        content: Container(
            constraints: const BoxConstraints(maxWidth: 240),
            child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const SizedBox(height: 30),
                  const Center(child: CircularProgressIndicator()),
                  const SizedBox(height: 20),
                  Center(
                      child: Text(translate(text),
                          style: const TextStyle(fontSize: 15))),
                  const SizedBox(height: 20),
                  Offstage(
                      offstage: !showCancel,
                      child: Center(
                          child: isDesktop
                              ? dialogButton('Cancel', onPressed: cancel)
                              : TextButton(
                                  style: flatButtonStyle,
                                  onPressed: cancel,
                                  child: Text(translate('Cancel'),
                                      style: const TextStyle(
                                          color: MyTheme.accent)))))
                ])),
        onCancel: showCancel ? cancel : null,
      );
    }, tag: tag);
    return tag;
  }

  void resetMobileActionsOverlay({FFI? ffi}) {
    if (_mobileActionsOverlayEntry == null) return;
    hideMobileActionsOverlay();
    showMobileActionsOverlay(ffi: ffi);
  }

  void showMobileActionsOverlay({FFI? ffi}) {
    if (_mobileActionsOverlayEntry != null) return;
    final overlayState = _overlayKeyState.state;
    if (overlayState == null) return;

    // compute overlay position
    final screenW = MediaQuery.of(globalKey.currentContext!).size.width;
    final screenH = MediaQuery.of(globalKey.currentContext!).size.height;
    const double overlayW = 200;
    const double overlayH = 45;
    final left = (screenW - overlayW) / 2;
    final top = screenH - overlayH - 80;

    final overlay = OverlayEntry(builder: (context) {
      final session = ffi ?? gFFI;
      return DraggableMobileActions(
        position: Offset(left, top),
        width: overlayW,
        height: overlayH,
        onBackPressed: () => session.inputModel.tap(MouseButtons.right),
        onHomePressed: () => session.inputModel.tap(MouseButtons.wheel),
        onRecentPressed: () async {
          session.inputModel.sendMouse('down', MouseButtons.wheel);
          await Future.delayed(const Duration(milliseconds: 500));
          session.inputModel.sendMouse('up', MouseButtons.wheel);
        },
        onHidePressed: () => hideMobileActionsOverlay(),
      );
    });
    overlayState.insert(overlay);
    _mobileActionsOverlayEntry = overlay;
    mobileActionsOverlayVisible.value = true;
  }

  void hideMobileActionsOverlay() {
    if (_mobileActionsOverlayEntry != null) {
      _mobileActionsOverlayEntry!.remove();
      _mobileActionsOverlayEntry = null;
      mobileActionsOverlayVisible.value = false;
      return;
    }
  }

  void toggleMobileActionsOverlay({FFI? ffi}) {
    if (_mobileActionsOverlayEntry == null) {
      showMobileActionsOverlay(ffi: ffi);
    } else {
      hideMobileActionsOverlay();
    }
  }

  bool existing(String tag) {
    return _dialogs.keys.contains(tag);
  }
}

void showToast(String text, {Duration timeout = const Duration(seconds: 2)}) {
  final overlayState = globalKey.currentState?.overlay;
  if (overlayState == null) return;
  final entry = OverlayEntry(builder: (_) {
    return IgnorePointer(
        child: Align(
            alignment: const Alignment(0.0, 0.8),
            child: Container(
              decoration: BoxDecoration(
                color: Colors.black.withOpacity(0.6),
                borderRadius: const BorderRadius.all(
                  Radius.circular(20),
                ),
              ),
              padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 5),
              child: Text(
                text,
                textAlign: TextAlign.center,
                style: const TextStyle(
                    decoration: TextDecoration.none,
                    fontWeight: FontWeight.w300,
                    fontSize: 18,
                    color: Colors.white),
              ),
            )));
  });
  overlayState.insert(entry);
  Future.delayed(timeout, () {
    entry.remove();
  });
}

// TODO
// - Remove argument "contentPadding", no need for it, all should look the same.
// - Remove "required" for argument "content". See simple confirm dialog "delete peer", only title and actions are used. No need to "content: SizedBox.shrink()".
// - Make dead code alive, transform arguments "onSubmit" and "onCancel" into correspondenting buttons "ConfirmOkButton", "CancelButton".
class CustomAlertDialog extends StatelessWidget {
  const CustomAlertDialog(
      {Key? key,
      this.title,
      this.titlePadding,
      required this.content,
      this.actions,
      this.contentPadding,
      this.contentBoxConstraints = const BoxConstraints(maxWidth: 500),
      this.onSubmit,
      this.onCancel})
      : super(key: key);

  final Widget? title;
  final EdgeInsetsGeometry? titlePadding;
  final Widget content;
  final List<Widget>? actions;
  final double? contentPadding;
  final BoxConstraints contentBoxConstraints;
  final Function()? onSubmit;
  final Function()? onCancel;

  @override
  Widget build(BuildContext context) {
    // request focus
    FocusScopeNode scopeNode = FocusScopeNode();
    Future.delayed(Duration.zero, () {
      if (!scopeNode.hasFocus) scopeNode.requestFocus();
    });
    bool tabTapped = false;
    if (isAndroid) gFFI.invokeMethod("enable_soft_keyboard", true);

    return FocusScope(
      node: scopeNode,
      autofocus: true,
      onKey: (node, key) {
        if (key.logicalKey == LogicalKeyboardKey.escape) {
          if (key is RawKeyDownEvent) {
            onCancel?.call();
          }
          return KeyEventResult.handled; // avoid TextField exception on escape
        } else if (!tabTapped &&
            onSubmit != null &&
            key.logicalKey == LogicalKeyboardKey.enter) {
          if (key is RawKeyDownEvent) onSubmit?.call();
          return KeyEventResult.handled;
        } else if (key.logicalKey == LogicalKeyboardKey.tab) {
          if (key is RawKeyDownEvent) {
            scopeNode.nextFocus();
            tabTapped = true;
          }
          return KeyEventResult.handled;
        }
        return KeyEventResult.ignored;
      },
      child: AlertDialog(
          scrollable: true,
          title: title,
          content: ConstrainedBox(
            constraints: contentBoxConstraints,
            child: content,
          ),
          actions: actions,
          titlePadding: titlePadding ?? MyTheme.dialogTitlePadding(),
          contentPadding:
              MyTheme.dialogContentPadding(actions: actions is List),
          actionsPadding: MyTheme.dialogActionsPadding(),
          buttonPadding: MyTheme.dialogButtonPadding),
    );
  }
}

void msgBox(SessionID sessionId, String type, String title, String text,
    String link, OverlayDialogManager dialogManager,
    {bool? hasCancel, ReconnectHandle? reconnect}) {
  dialogManager.dismissAll();
  List<Widget> buttons = [];
  bool hasOk = false;
  submit() {
    dialogManager.dismissAll();
    // https://github.com/fufesou/rustdesk/blob/5e9a31340b899822090a3731769ae79c6bf5f3e5/src/ui/common.tis#L263
    if (!type.contains("custom") && desktopType != DesktopType.portForward) {
      closeConnection();
    }
  }

  cancel() {
    dialogManager.dismissAll();
  }

  jumplink() {
    if (link.startsWith('http')) {
      launchUrl(Uri.parse(link));
    }
  }

  if (type != "connecting" && type != "success" && !type.contains("nook")) {
    hasOk = true;
    buttons.insert(0, dialogButton('OK', onPressed: submit));
  }
  hasCancel ??= !type.contains("error") &&
      !type.contains("nocancel") &&
      type != "restarting";
  if (hasCancel) {
    buttons.insert(
        0, dialogButton('Cancel', onPressed: cancel, isOutline: true));
  }
  if (type.contains("hasclose")) {
    buttons.insert(
        0,
        dialogButton('Close', onPressed: () {
          dialogManager.dismissAll();
        }));
  }
  if (reconnect != null && title == "Connection Error") {
    // `enabled` is used to disable the dialog button once the button is clicked.
    final enabled = true.obs;
    final button = Obx(
      () => dialogButton(
        'Reconnect',
        isOutline: true,
        onPressed: enabled.isTrue
            ? () {
                // Disable the button
                enabled.value = false;
                reconnect(dialogManager, sessionId, false);
              }
            : null,
      ),
    );
    buttons.insert(0, button);
  }
  if (link.isNotEmpty) {
    buttons.insert(0, dialogButton('JumpLink', onPressed: jumplink));
  }
  dialogManager.show(
    (setState, close, context) => CustomAlertDialog(
      title: null,
      content: SelectionArea(child: msgboxContent(type, title, text)),
      actions: buttons,
      onSubmit: hasOk ? submit : null,
      onCancel: hasCancel == true ? cancel : null,
    ),
    tag: '$sessionId-$type-$title-$text-$link',
  );
}

Color? _msgboxColor(String type) {
  if (type == "input-password" || type == "custom-os-password") {
    return Color(0xFFAD448E);
  }
  if (type.contains("success")) {
    return Color(0xFF32bea6);
  }
  if (type.contains("error") || type == "re-input-password") {
    return Color(0xFFE04F5F);
  }
  return Color(0xFF2C8CFF);
}

Widget msgboxIcon(String type) {
  IconData? iconData;
  if (type.contains("error") || type == "re-input-password") {
    iconData = Icons.cancel;
  }
  if (type.contains("success")) {
    iconData = Icons.check_circle;
  }
  if (type == "wait-uac" || type == "wait-remote-accept-nook") {
    iconData = Icons.hourglass_top;
  }
  if (type == 'on-uac' || type == 'on-foreground-elevated') {
    iconData = Icons.admin_panel_settings;
  }
  if (type.contains('info')) {
    iconData = Icons.info;
  }
  if (iconData != null) {
    return Icon(iconData, size: 50, color: _msgboxColor(type))
        .marginOnly(right: 16);
  }

  return Offstage();
}

// title should be null
Widget msgboxContent(String type, String title, String text) {
  String translateText(String text) {
    if (text.indexOf('Failed') == 0 && text.indexOf(': ') > 0) {
      List<String> words = text.split(': ');
      for (var i = 0; i < words.length; ++i) {
        words[i] = translate(words[i]);
      }
      text = words.join(': ');
    } else {
      List<String> words = text.split(' ');
      if (words.length > 1 && words[0].endsWith('_tip')) {
        words[0] = translate(words[0]);
        final rest = text.substring(words[0].length + 1);
        text = '${words[0]} ${translate(rest)}';
      } else {
        text = translate(text);
      }
    }
    return text;
  }

  return Row(
    children: [
      msgboxIcon(type),
      Expanded(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              translate(title),
              style: TextStyle(fontSize: 21),
            ).marginOnly(bottom: 10),
            Text(translateText(text), style: const TextStyle(fontSize: 15)),
          ],
        ),
      ),
    ],
  ).marginOnly(bottom: 12);
}

void msgBoxCommon(OverlayDialogManager dialogManager, String title,
    Widget content, List<Widget> buttons,
    {bool hasCancel = true}) {
  dialogManager.show((setState, close, context) => CustomAlertDialog(
        title: Text(
          translate(title),
          style: TextStyle(fontSize: 21),
        ),
        content: content,
        actions: buttons,
        onCancel: hasCancel ? close : null,
      ));
}

Color str2color(String str, [alpha = 0xFF]) {
  var hash = 160 << 16 + 114 << 8 + 91;
  for (var i = 0; i < str.length; i += 1) {
    hash = str.codeUnitAt(i) + ((hash << 5) - hash);
  }
  hash = hash % 16777216;
  return Color((hash & 0xFF7FFF) | (alpha << 24));
}

Color str2color2(String str, {List<int> existing = const []}) {
  Map<String, Color> colorMap = {
    "red": Colors.red,
    "green": Colors.green,
    "blue": Colors.blue,
    "orange": Colors.orange,
    "purple": Colors.purple,
    "grey": Colors.grey,
    "cyan": Colors.cyan,
    "lime": Colors.lime,
    "teal": Colors.teal,
    "pink": Colors.pink[200]!,
    "indigo": Colors.indigo,
    "brown": Colors.brown,
  };
  final color = colorMap[str.toLowerCase()];
  if (color != null) {
    return color.withAlpha(0xFF);
  }
  if (str.toLowerCase() == 'yellow') {
    return Colors.yellow.withAlpha(0xFF);
  }
  var hash = 0;
  for (var i = 0; i < str.length; i++) {
    hash += str.codeUnitAt(i);
  }
  List<Color> colorList = colorMap.values.toList();
  hash = hash % colorList.length;
  var result = colorList[hash].withAlpha(0xFF);
  if (existing.contains(result.value)) {
    Color? notUsed =
        colorList.firstWhereOrNull((e) => !existing.contains(e.value));
    if (notUsed != null) {
      result = notUsed;
    }
  }
  return result;
}

const K = 1024;
const M = K * K;
const G = M * K;

String readableFileSize(double size) {
  if (size < K) {
    return "${size.toStringAsFixed(2)} B";
  } else if (size < M) {
    return "${(size / K).toStringAsFixed(2)} KB";
  } else if (size < G) {
    return "${(size / M).toStringAsFixed(2)} MB";
  } else {
    return "${(size / G).toStringAsFixed(2)} GB";
  }
}

/// Flutter can't not catch PointerMoveEvent when size is 1
/// This will happen in Android AccessibilityService Input
/// android can't init dispatching size yet ,see: https://stackoverflow.com/questions/59960451/android-accessibility-dispatchgesture-is-it-possible-to-specify-pressure-for-a
/// use this temporary solution until flutter or android fixes the bug
class AccessibilityListener extends StatelessWidget {
  final Widget? child;
  static final offset = 100;

  AccessibilityListener({this.child});

  @override
  Widget build(BuildContext context) {
    return Listener(
        onPointerDown: (evt) {
          if (evt.size == 1) {
            GestureBinding.instance.handlePointerEvent(PointerAddedEvent(
                pointer: evt.pointer + offset, position: evt.position));
            GestureBinding.instance.handlePointerEvent(PointerDownEvent(
                pointer: evt.pointer + offset,
                size: 0.1,
                position: evt.position));
          }
        },
        onPointerUp: (evt) {
          if (evt.size == 1) {
            GestureBinding.instance.handlePointerEvent(PointerUpEvent(
                pointer: evt.pointer + offset,
                size: 0.1,
                position: evt.position));
            GestureBinding.instance.handlePointerEvent(PointerRemovedEvent(
                pointer: evt.pointer + offset, position: evt.position));
          }
        },
        onPointerMove: (evt) {
          if (evt.size == 1) {
            GestureBinding.instance.handlePointerEvent(PointerMoveEvent(
                pointer: evt.pointer + offset,
                size: 0.1,
                delta: evt.delta,
                position: evt.position));
          }
        },
        child: child);
  }
}

class AndroidPermissionManager {
  static Completer<bool>? _completer;
  static Timer? _timer;
  static var _current = "";

  static bool isWaitingFile() {
    if (_completer != null) {
      return !_completer!.isCompleted && _current == kManageExternalStorage;
    }
    return false;
  }

  static Future<bool> check(String type) {
    if (isDesktop) {
      return Future.value(true);
    }
    return gFFI.invokeMethod("check_permission", type);
  }

  // startActivity goto Android Setting's page to request permission manually by user
  static void startAction(String action) {
    gFFI.invokeMethod(AndroidChannel.kStartAction, action);
  }

  /// We use XXPermissions to request permissions,
  /// for supported types, see https://github.com/getActivity/XXPermissions/blob/e46caea32a64ad7819df62d448fb1c825481cd28/library/src/main/java/com/hjq/permissions/Permission.java
  static Future<bool> request(String type) {
    if (isDesktop) {
      return Future.value(true);
    }

    gFFI.invokeMethod("request_permission", type);

    // clear last task
    if (_completer?.isCompleted == false) {
      _completer?.complete(false);
    }
    _timer?.cancel();

    _current = type;
    _completer = Completer<bool>();

    _timer = Timer(Duration(seconds: 120), () {
      if (_completer == null) return;
      if (!_completer!.isCompleted) {
        _completer!.complete(false);
      }
      _completer = null;
      _current = "";
    });
    return _completer!.future;
  }

  static complete(String type, bool res) {
    if (type != _current) {
      res = false;
    }
    _timer?.cancel();
    _completer?.complete(res);
    _current = "";
  }
}

// TODO move this to mobile/widgets.
// Used only for mobile, pages remote, settings, dialog
// TODO remove argument contentPadding, it’s not used, getToggle() has not
RadioListTile<T> getRadio<T>(
    Widget title, T toValue, T curValue, ValueChanged<T?>? onChange,
    {EdgeInsetsGeometry? contentPadding, bool? dense}) {
  return RadioListTile<T>(
    contentPadding: contentPadding ?? EdgeInsets.zero,
    visualDensity: VisualDensity.compact,
    controlAffinity: ListTileControlAffinity.trailing,
    title: title,
    value: toValue,
    groupValue: curValue,
    onChanged: onChange,
    dense: dense,
  );
}

/// find ffi, tag is Remote ID
/// for session specific usage
FFI ffi(String? tag) {
  return Get.find<FFI>(tag: tag);
}

/// Global FFI object
late FFI _globalFFI;

FFI get gFFI => _globalFFI;

Future<void> initGlobalFFI() async {
  debugPrint("_globalFFI init");
  _globalFFI = FFI(null);
  debugPrint("_globalFFI init end");
  // after `put`, can also be globally found by Get.find<FFI>();
  Get.put(_globalFFI, permanent: true);
}

String translate(String name) {
  if (name.startsWith('Failed to') && name.contains(': ')) {
    return name.split(': ').map((x) => translate(x)).join(': ');
  }
  return platformFFI.translate(name, localeName);
}

bool option2bool(String option, String value) {
  bool res;
  if (option.startsWith("enable-")) {
    res = value != "N";
  } else if (option.startsWith("allow-") ||
      option == "stop-service" ||
      option == "direct-server" ||
      option == "stop-rendezvous-service" ||
      option == kOptionForceAlwaysRelay) {
    res = value == "Y";
  } else {
    assert(false);
    res = value != "N";
  }
  return res;
}

String bool2option(String option, bool b) {
  String res;
  if (option.startsWith('enable-')) {
    res = b ? '' : 'N';
  } else if (option.startsWith('allow-') ||
      option == "stop-service" ||
      option == "direct-server" ||
      option == "stop-rendezvous-service" ||
      option == kOptionForceAlwaysRelay) {
    res = b ? 'Y' : '';
  } else {
    assert(false);
    res = b ? 'Y' : 'N';
  }
  return res;
}

mainSetBoolOption(String key, bool value) async {
  String v = bool2option(key, value);
  await bind.mainSetOption(key: key, value: v);
}

Future<bool> mainGetBoolOption(String key) async {
  return option2bool(key, await bind.mainGetOption(key: key));
}

bool mainGetBoolOptionSync(String key) {
  return option2bool(key, bind.mainGetOptionSync(key: key));
}

mainSetLocalBoolOption(String key, bool value) async {
  String v = bool2option(key, value);
  await bind.mainSetLocalOption(key: key, value: v);
}

bool mainGetLocalBoolOptionSync(String key) {
  return option2bool(key, bind.mainGetLocalOption(key: key));
}

bool mainGetPeerBoolOptionSync(String id, String key) {
  return option2bool(key, bind.mainGetPeerOptionSync(id: id, key: key));
}

mainSetPeerBoolOptionSync(String id, String key, bool v) {
  bind.mainSetPeerOptionSync(id: id, key: key, value: bool2option(key, v));
}

Future<bool> matchPeer(String searchText, Peer peer) async {
  if (searchText.isEmpty) {
    return true;
  }
  if (peer.id.toLowerCase().contains(searchText)) {
    return true;
  }
  if (peer.hostname.toLowerCase().contains(searchText) ||
      peer.username.toLowerCase().contains(searchText)) {
    return true;
  }
  final alias = peer.alias;
  if (alias.isEmpty) {
    return false;
  }
  return alias.toLowerCase().contains(searchText);
}

/// Get the image for the current [platform].
Widget getPlatformImage(String platform, {double size = 50}) {
  if (platform.isEmpty) {
    return Container(width: size, height: size);
  }
  if (platform == kPeerPlatformMacOS) {
    platform = 'mac';
  } else if (platform != kPeerPlatformLinux &&
      platform != kPeerPlatformAndroid) {
    platform = 'win';
  } else {
    platform = platform.toLowerCase();
  }
  return SvgPicture.asset('assets/$platform.svg', height: size, width: size);
}

class LastWindowPosition {
  double? width;
  double? height;
  double? offsetWidth;
  double? offsetHeight;
  bool? isMaximized;
  bool? isFullscreen;

  LastWindowPosition(this.width, this.height, this.offsetWidth,
      this.offsetHeight, this.isMaximized, this.isFullscreen);

  Map<String, dynamic> toJson() {
    return <String, dynamic>{
      "width": width,
      "height": height,
      "offsetWidth": offsetWidth,
      "offsetHeight": offsetHeight,
      "isMaximized": isMaximized,
      "isFullscreen": isFullscreen,
    };
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }

  static LastWindowPosition? loadFromString(String content) {
    if (content.isEmpty) {
      return null;
    }
    try {
      final m = jsonDecode(content);
      return LastWindowPosition(m["width"], m["height"], m["offsetWidth"],
          m["offsetHeight"], m["isMaximized"], m["isFullscreen"]);
    } catch (e) {
      debugPrintStack(
          label:
              'Failed to load LastWindowPosition "$content" ${e.toString()}');
      return null;
    }
  }
}

/// Save window position and size on exit
/// Note that windowId must be provided if it's subwindow
Future<void> saveWindowPosition(WindowType type, {int? windowId}) async {
  if (type != WindowType.Main && windowId == null) {
    debugPrint(
        "Error: windowId cannot be null when saving positions for sub window");
  }

  late Offset position;
  late Size sz;
  late bool isMaximized;
  bool isFullscreen = stateGlobal.fullscreen.isTrue ||
      (Platform.isMacOS && stateGlobal.closeOnFullscreen == true);
  setFrameIfMaximized() {
    if (isMaximized) {
      final pos = bind.getLocalFlutterOption(k: kWindowPrefix + type.name);
      var lpos = LastWindowPosition.loadFromString(pos);
      position = Offset(
          lpos?.offsetWidth ?? position.dx, lpos?.offsetHeight ?? position.dy);
      sz = Size(lpos?.width ?? sz.width, lpos?.height ?? sz.height);
    }
  }

  switch (type) {
    case WindowType.Main:
      isMaximized = await windowManager.isMaximized();
      position = await windowManager.getPosition();
      sz = await windowManager.getSize();
      setFrameIfMaximized();
      break;
    default:
      final wc = WindowController.fromWindowId(windowId!);
      isMaximized = await wc.isMaximized();
      final Rect frame;
      try {
        frame = await wc.getFrame();
      } catch (e) {
        debugPrint("Failed to get frame of window $windowId, it may be hidden");
        return;
      }
      position = frame.topLeft;
      sz = frame.size;
      setFrameIfMaximized();
      break;
  }
  if (Platform.isWindows) {
    const kMinOffset = -10000;
    const kMaxOffset = 10000;
    if (position.dx < kMinOffset ||
        position.dy < kMinOffset ||
        position.dx > kMaxOffset ||
        position.dy > kMaxOffset) {
      debugPrint("Invalid position: $position, ignore saving position");
      return;
    }
  }

  final pos = LastWindowPosition(
      sz.width, sz.height, position.dx, position.dy, isMaximized, isFullscreen);
  debugPrint(
      "Saving frame: $windowId: ${pos.width}/${pos.height}, offset:${pos.offsetWidth}/${pos.offsetHeight}, isMaximized:${pos.isMaximized}, isFullscreen:${pos.isFullscreen}");

  await bind.setLocalFlutterOption(
      k: kWindowPrefix + type.name, v: pos.toString());

  if (type == WindowType.RemoteDesktop && windowId != null) {
    await _saveSessionWindowPosition(
        type, windowId, isMaximized, isFullscreen, pos);
  }
}

Future _saveSessionWindowPosition(WindowType windowType, int windowId,
    bool isMaximized, bool isFullscreen, LastWindowPosition pos) async {
  final remoteList = await DesktopMultiWindow.invokeMethod(
      windowId, kWindowEventGetRemoteList, null);
  getPeerPos(String peerId) {
    if (isMaximized) {
      final peerPos = bind.mainGetPeerFlutterOptionSync(
          id: peerId, k: kWindowPrefix + windowType.name);
      var lpos = LastWindowPosition.loadFromString(peerPos);
      return LastWindowPosition(
              lpos?.width ?? pos.offsetWidth,
              lpos?.height ?? pos.offsetHeight,
              lpos?.offsetWidth ?? pos.offsetWidth,
              lpos?.offsetHeight ?? pos.offsetHeight,
              isMaximized,
              isFullscreen)
          .toString();
    } else {
      return pos.toString();
    }
  }

  if (remoteList != null) {
    for (final peerId in remoteList.split(',')) {
      bind.mainSetPeerFlutterOptionSync(
          id: peerId,
          k: kWindowPrefix + windowType.name,
          v: getPeerPos(peerId));
    }
  }
}

Future<Size> _adjustRestoreMainWindowSize(double? width, double? height) async {
  const double minWidth = 1;
  const double minHeight = 1;
  const double maxWidth = 6480;
  const double maxHeight = 6480;

  final defaultWidth =
      ((isDesktop || isWebDesktop) ? 1280 : kMobileDefaultDisplayWidth)
          .toDouble();
  final defaultHeight =
      ((isDesktop || isWebDesktop) ? 720 : kMobileDefaultDisplayHeight)
          .toDouble();
  double restoreWidth = width ?? defaultWidth;
  double restoreHeight = height ?? defaultHeight;

  if (restoreWidth < minWidth) {
    restoreWidth = defaultWidth;
  }
  if (restoreHeight < minHeight) {
    restoreHeight = defaultHeight;
  }
  if (restoreWidth > maxWidth) {
    restoreWidth = defaultWidth;
  }
  if (restoreHeight > maxHeight) {
    restoreHeight = defaultHeight;
  }
  return Size(restoreWidth, restoreHeight);
}

/// return null means center
Future<Offset?> _adjustRestoreMainWindowOffset(
  double? left,
  double? top,
  double? width,
  double? height,
) async {
  if (left == null || top == null || width == null || height == null) {
    return null;
  }

  double? frameLeft;
  double? frameTop;
  double? frameRight;
  double? frameBottom;

  if (isDesktop || isWebDesktop) {
    for (final screen in await window_size.getScreenList()) {
      frameLeft = frameLeft == null
          ? screen.visibleFrame.left
          : min(screen.visibleFrame.left, frameLeft);
      frameTop = frameTop == null
          ? screen.visibleFrame.top
          : min(screen.visibleFrame.top, frameTop);
      frameRight = frameRight == null
          ? screen.visibleFrame.right
          : max(screen.visibleFrame.right, frameRight);
      frameBottom = frameBottom == null
          ? screen.visibleFrame.bottom
          : max(screen.visibleFrame.bottom, frameBottom);
    }
  }
  if (frameLeft == null) {
    frameLeft = 0.0;
    frameTop = 0.0;
    frameRight = ((isDesktop || isWebDesktop)
            ? kDesktopMaxDisplaySize
            : kMobileMaxDisplaySize)
        .toDouble();
    frameBottom = ((isDesktop || isWebDesktop)
            ? kDesktopMaxDisplaySize
            : kMobileMaxDisplaySize)
        .toDouble();
  }
  final minWidth = 10.0;
  if ((left + minWidth) > frameRight! ||
      (top + minWidth) > frameBottom! ||
      (left + width - minWidth) < frameLeft ||
      top < frameTop!) {
    return null;
  } else {
    return Offset(left, top);
  }
}

/// Restore window position and size on start
/// Note that windowId must be provided if it's subwindow
//
// display is used to set the offset of the window in individual display mode.
Future<bool> restoreWindowPosition(WindowType type,
    {int? windowId, String? peerId, int? display}) async {
  if (bind
      .mainGetEnv(key: "DISABLE_RUSTDESK_RESTORE_WINDOW_POSITION")
      .isNotEmpty) {
    return false;
  }
  if (type != WindowType.Main && windowId == null) {
    debugPrint(
        "Error: windowId cannot be null when saving positions for sub window");
    return false;
  }

  bool isRemotePeerPos = false;
  String? pos;
  // No need to check mainGetLocalBoolOptionSync(kOptionOpenNewConnInTabs)
  // Though "open in tabs" is true and the new window restore peer position, it's ok.
  if (type == WindowType.RemoteDesktop && windowId != null && peerId != null) {
    // If the restore position is called by main window, and the peer id is not null
    // then we may need to get the position by reading the peer config.
    // Because the session may not be read at this time.
    if (desktopType == DesktopType.main) {
      pos = bind.mainGetPeerFlutterOptionSync(
          id: peerId, k: kWindowPrefix + type.name);
    } else {
      pos = await bind.sessionGetFlutterOptionByPeerId(
          id: peerId, k: kWindowPrefix + type.name);
    }
    isRemotePeerPos = pos != null;
  }
  pos ??= bind.getLocalFlutterOption(k: kWindowPrefix + type.name);

  var lpos = LastWindowPosition.loadFromString(pos);
  if (lpos == null) {
    debugPrint("no window position saved, ignoring position restoration");
    return false;
  }
  if (type == WindowType.RemoteDesktop) {
    if (!isRemotePeerPos && windowId != null) {
      if (lpos.offsetWidth != null) {
        lpos.offsetWidth = lpos.offsetWidth! + windowId * kNewWindowOffset;
      }
      if (lpos.offsetHeight != null) {
        lpos.offsetHeight = lpos.offsetHeight! + windowId * kNewWindowOffset;
      }
    }
    if (display != null) {
      if (lpos.offsetWidth != null) {
        lpos.offsetWidth = lpos.offsetWidth! + display * kNewWindowOffset;
      }
      if (lpos.offsetHeight != null) {
        lpos.offsetHeight = lpos.offsetHeight! + display * kNewWindowOffset;
      }
    }
  }

  final size = await _adjustRestoreMainWindowSize(lpos.width, lpos.height);
  final offset = await _adjustRestoreMainWindowOffset(
    lpos.offsetWidth,
    lpos.offsetHeight,
    size.width,
    size.height,
  );
  debugPrint(
      "restore lpos: ${size.width}/${size.height}, offset:${offset?.dx}/${offset?.dy}");

  switch (type) {
    case WindowType.Main:
      restorePos() async {
        if (offset == null) {
          await windowManager.center();
        } else {
          await windowManager.setPosition(offset);
        }
      }
      if (lpos.isMaximized == true) {
        await restorePos();
        await windowManager.maximize();
      } else {
        await windowManager.setSize(size);
        await restorePos();
      }
      return true;
    default:
      final wc = WindowController.fromWindowId(windowId!);
      restoreFrame() async {
        if (offset == null) {
          await wc.center();
        } else {
          final frame =
              Rect.fromLTWH(offset.dx, offset.dy, size.width, size.height);
          await wc.setFrame(frame);
        }
      }
      if (lpos.isFullscreen == true) {
        await restoreFrame();
        // An duration is needed to avoid the window being restored after fullscreen.
        Future.delayed(Duration(milliseconds: 300), () async {
          stateGlobal.setFullscreen(true);
        });
      } else if (lpos.isMaximized == true) {
        await restoreFrame();
        // An duration is needed to avoid the window being restored after maximized.
        Future.delayed(Duration(milliseconds: 300), () async {
          await wc.maximize();
        });
      } else {
        await restoreFrame();
      }
      break;
  }
  return false;
}

/// Initialize uni links for macos/windows
///
/// [Availability]
/// initUniLinks should only be used on macos/windows.
/// we use dbus for linux currently.
Future<bool> initUniLinks() async {
  if (Platform.isLinux) {
    return false;
  }
  // check cold boot
  try {
    final initialLink = await getInitialLink();
    if (initialLink == null) {
      return false;
    }
    return handleUriLink(uriString: initialLink);
  } catch (err) {
    debugPrintStack(label: "$err");
    return false;
  }
}

/// Listen for uni links.
///
/// * handleByFlutter: Should uni links be handled by Flutter.
///
/// Returns a [StreamSubscription] which can listen the uni links.
StreamSubscription? listenUniLinks({handleByFlutter = true}) {
  if (Platform.isLinux) {
    return null;
  }

  final sub = uriLinkStream.listen((Uri? uri) {
    debugPrint("A uri was received: $uri. handleByFlutter $handleByFlutter");
    if (uri != null) {
      if (handleByFlutter) {
        handleUriLink(uri: uri);
      } else {
        bind.sendUrlScheme(url: uri.toString());
      }
    } else {
      print("uni listen error: uri is empty.");
    }
  }, onError: (err) {
    print("uni links error: $err");
  });
  return sub;
}

enum UriLinkType {
  remoteDesktop,
  fileTransfer,
  portForward,
  rdp,
}

// uri link handler
bool handleUriLink({List<String>? cmdArgs, Uri? uri, String? uriString}) {
  List<String>? args;
  if (cmdArgs != null && cmdArgs.isNotEmpty) {
    args = cmdArgs;
    // rustdesk <uri link>
    if (args[0].startsWith(kUniLinksPrefix)) {
      final uri = Uri.tryParse(args[0]);
      if (uri != null) {
        args = urlLinkToCmdArgs(uri);
      }
    }
  } else if (uri != null) {
    args = urlLinkToCmdArgs(uri);
  } else if (uriString != null) {
    final uri = Uri.tryParse(uriString);
    if (uri != null) {
      args = urlLinkToCmdArgs(uri);
    }
  }
  if (args == null) {
    return false;
  }

  if (args.isEmpty) {
    windowOnTop(null);
    return true;
  }

  UriLinkType? type;
  String? id;
  String? password;
  String? switchUuid;
  bool? forceRelay;
  for (int i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--connect':
      case '--play':
        type = UriLinkType.remoteDesktop;
        id = args[i + 1];
        i++;
        break;
      case '--file-transfer':
        type = UriLinkType.fileTransfer;
        id = args[i + 1];
        i++;
        break;
      case '--port-forward':
        type = UriLinkType.portForward;
        id = args[i + 1];
        i++;
        break;
      case '--rdp':
        type = UriLinkType.rdp;
        id = args[i + 1];
        i++;
        break;
      case '--password':
        password = args[i + 1];
        i++;
        break;
      case '--switch_uuid':
        switchUuid = args[i + 1];
        i++;
        break;
      case '--relay':
        forceRelay = true;
        break;
      default:
        break;
    }
  }
  if (type != null && id != null) {
    switch (type) {
      case UriLinkType.remoteDesktop:
        Future.delayed(Duration.zero, () {
          rustDeskWinManager.newRemoteDesktop(id!,
              password: password,
              switchUuid: switchUuid,
              forceRelay: forceRelay);
        });
        break;
      case UriLinkType.fileTransfer:
        Future.delayed(Duration.zero, () {
          rustDeskWinManager.newFileTransfer(id!,
              password: password, forceRelay: forceRelay);
        });
        break;
      case UriLinkType.portForward:
        Future.delayed(Duration.zero, () {
          rustDeskWinManager.newPortForward(id!, false,
              password: password, forceRelay: forceRelay);
        });
        break;
      case UriLinkType.rdp:
        Future.delayed(Duration.zero, () {
          rustDeskWinManager.newPortForward(id!, true,
              password: password, forceRelay: forceRelay);
        });
        break;
    }

    return true;
  }

  return false;
}

List<String>? urlLinkToCmdArgs(Uri uri) {
  String? command;
  String? id;
  if (uri.authority.isEmpty &&
      uri.path.split('').every((char) => char == '/')) {
    return [];
  } else if (uri.authority == "connection" && uri.path.startsWith("/new/")) {
    // For compatibility
    command = '--connect';
    id = uri.path.substring("/new/".length);
  } else if (['connect', "play", 'file-transfer', 'port-forward', 'rdp']
      .contains(uri.authority)) {
    command = '--${uri.authority}';
    if (uri.path.length > 1) {
      id = uri.path.substring(1);
    }
  } else if (uri.authority.length > 2 && uri.path.length <= 1) {
    // rustdesk://<connect-id>
    command = '--connect';
    id = uri.authority;
  }

  List<String> args = List.empty(growable: true);
  if (command != null && id != null) {
    args.add(command);
    args.add(id);
    var param = uri.queryParameters;
    String? password = param["password"];
    if (password != null) args.addAll(['--password', password]);
    String? switch_uuid = param["switch_uuid"];
    if (switch_uuid != null) args.addAll(['--switch_uuid', switch_uuid]);
    if (param["relay"] != null) args.add("--relay");
    return args;
  }

  return null;
}

connectMainDesktop(
  String id, {
  required bool isFileTransfer,
  required bool isTcpTunneling,
  required bool isRDP,
  bool? forceRelay,
}) async {
  if (isFileTransfer) {
    await rustDeskWinManager.newFileTransfer(id, forceRelay: forceRelay);
  } else if (isTcpTunneling || isRDP) {
    await rustDeskWinManager.newPortForward(id, isRDP, forceRelay: forceRelay);
  } else {
    await rustDeskWinManager.newRemoteDesktop(id, forceRelay: forceRelay);
  }
}

/// Connect to a peer with [id].
/// If [isFileTransfer], starts a session only for file transfer.
/// If [isTcpTunneling], starts a session only for tcp tunneling.
/// If [isRDP], starts a session only for rdp.
connect(
  BuildContext context,
  String id, {
  bool isFileTransfer = false,
  bool isTcpTunneling = false,
  bool isRDP = false,
}) async {
  if (id == '') return;
  if (!isDesktop || desktopType == DesktopType.main) {
    try {
      if (Get.isRegistered<IDTextEditingController>()) {
        final idController = Get.find<IDTextEditingController>();
        idController.text = formatID(id);
      }
    } catch (_) {}
  }
  id = id.replaceAll(' ', '');
  final oldId = id;
  id = await bind.mainHandleRelayId(id: id);
  final forceRelay = id != oldId;
  assert(!(isFileTransfer && isTcpTunneling && isRDP),
      "more than one connect type");

  if (isDesktop) {
    if (desktopType == DesktopType.main) {
      await connectMainDesktop(
        id,
        isFileTransfer: isFileTransfer,
        isTcpTunneling: isTcpTunneling,
        isRDP: isRDP,
        forceRelay: forceRelay,
      );
    } else {
      await rustDeskWinManager.call(WindowType.Main, kWindowConnect, {
        'id': id,
        'isFileTransfer': isFileTransfer,
        'isTcpTunneling': isTcpTunneling,
        'isRDP': isRDP,
        'forceRelay': forceRelay,
      });
    }
  } else {
    if (isFileTransfer) {
      if (!await AndroidPermissionManager.check(kManageExternalStorage)) {
        if (!await AndroidPermissionManager.request(kManageExternalStorage)) {
          return;
        }
      }
      Navigator.push(
        context,
        MaterialPageRoute(
          builder: (BuildContext context) => FileManagerPage(id: id),
        ),
      );
    } else {
      Navigator.push(
        context,
        MaterialPageRoute(
          builder: (BuildContext context) => RemotePage(id: id),
        ),
      );
    }
  }

  FocusScopeNode currentFocus = FocusScope.of(context);
  if (!currentFocus.hasPrimaryFocus) {
    currentFocus.unfocus();
  }
}

Map<String, String> getHttpHeaders() {
  return {
    'Authorization': 'Bearer ${bind.mainGetLocalOption(key: 'access_token')}'
  };
}

// Simple wrapper of built-in types for reference use.
class SimpleWrapper<T> {
  T value;
  SimpleWrapper(this.value);
}

/// call this to reload current window.
///
/// [Note]
/// Must have [RefreshWrapper] on the top of widget tree.
void reloadCurrentWindow() {
  if (Get.context != null) {
    // reload self window
    RefreshWrapper.of(Get.context!)?.rebuild();
  } else {
    debugPrint(
        "reload current window failed, global BuildContext does not exist");
  }
}

/// call this to reload all windows, including main + all sub windows.
Future<void> reloadAllWindows() async {
  reloadCurrentWindow();
  try {
    final ids = await DesktopMultiWindow.getAllSubWindowIds();
    for (final id in ids) {
      DesktopMultiWindow.invokeMethod(id, kWindowActionRebuild);
    }
  } on AssertionError {
    // ignore
  }
}

/// Indicate the flutter app is running in portable mode.
///
/// [Note]
/// Portable build is only available on Windows.
bool isRunningInPortableMode() {
  if (!Platform.isWindows) {
    return false;
  }
  return bool.hasEnvironment(kEnvPortableExecutable);
}

/// Window status callback
Future<void> onActiveWindowChanged() async {
  print(
      "[MultiWindowHandler] active window changed: ${rustDeskWinManager.getActiveWindows()}");
  if (rustDeskWinManager.getActiveWindows().isEmpty) {
    // close all sub windows
    try {
      if (Platform.isLinux) {
        await Future.wait([
          saveWindowPosition(WindowType.Main),
          rustDeskWinManager.closeAllSubWindows()
        ]);
      } else {
        await rustDeskWinManager.closeAllSubWindows();
      }
    } catch (err) {
      debugPrintStack(label: "$err");
    } finally {
      debugPrint("Start closing RustDesk...");
      await windowManager.setPreventClose(false);
      await windowManager.close();
      if (Platform.isMacOS) {
        RdPlatformChannel.instance.terminate();
      }
    }
  }
}

Timer periodic_immediate(Duration duration, Future<void> Function() callback) {
  Future.delayed(Duration.zero, callback);
  return Timer.periodic(duration, (timer) async {
    await callback();
  });
}

/// return a human readable windows version
WindowsTarget getWindowsTarget(int buildNumber) {
  if (!Platform.isWindows) {
    return WindowsTarget.naw;
  }
  if (buildNumber >= 22000) {
    return WindowsTarget.w11;
  } else if (buildNumber >= 10240) {
    return WindowsTarget.w10;
  } else if (buildNumber >= 9600) {
    return WindowsTarget.w8_1;
  } else if (buildNumber >= 9200) {
    return WindowsTarget.w8;
  } else if (buildNumber >= 7601) {
    return WindowsTarget.w7;
  } else if (buildNumber >= 6002) {
    return WindowsTarget.vista;
  } else {
    // minimum support
    return WindowsTarget.xp;
  }
}

/// Get windows target build number.
///
/// [Note]
/// Please use this function wrapped with `Platform.isWindows`.
int getWindowsTargetBuildNumber() {
  final rtlGetVersion = DynamicLibrary.open('ntdll.dll').lookupFunction<
      Void Function(Pointer<win32.OSVERSIONINFOEX>),
      void Function(Pointer<win32.OSVERSIONINFOEX>)>('RtlGetVersion');
  final osVersionInfo = getOSVERSIONINFOEXPointer();
  rtlGetVersion(osVersionInfo);
  int buildNumber = osVersionInfo.ref.dwBuildNumber;
  calloc.free(osVersionInfo);
  return buildNumber;
}

/// Get Windows OS version pointer
///
/// [Note]
/// Please use this function wrapped with `Platform.isWindows`.
Pointer<win32.OSVERSIONINFOEX> getOSVERSIONINFOEXPointer() {
  final pointer = calloc<win32.OSVERSIONINFOEX>();
  pointer.ref
    ..dwOSVersionInfoSize = sizeOf<win32.OSVERSIONINFOEX>()
    ..dwBuildNumber = 0
    ..dwMajorVersion = 0
    ..dwMinorVersion = 0
    ..dwPlatformId = 0
    ..szCSDVersion = ''
    ..wServicePackMajor = 0
    ..wServicePackMinor = 0
    ..wSuiteMask = 0
    ..wProductType = 0
    ..wReserved = 0;
  return pointer;
}

/// Indicating we need to use compatible ui mode.
///
/// [Conditions]
/// - Windows 7, window will overflow when we use frameless ui.
bool get kUseCompatibleUiMode =>
    Platform.isWindows &&
    const [WindowsTarget.w7].contains(windowsBuildNumber.windowsVersion);

class ServerConfig {
  late String idServer;
  late String relayServer;
  late String apiServer;
  late String key;

  ServerConfig(
      {String? idServer, String? relayServer, String? apiServer, String? key}) {
    this.idServer = idServer?.trim() ?? '';
    this.relayServer = relayServer?.trim() ?? '';
    this.apiServer = apiServer?.trim() ?? '';
    this.key = key?.trim() ?? '';
  }

  /// decode from shared string (from user shared or rustdesk-server generated)
  /// also see [encode]
  /// throw when decoding failure
  ServerConfig.decode(String msg) {
    var json = {};
    try {
      // back compatible
      json = jsonDecode(msg);
    } catch (err) {
      final input = msg.split('').reversed.join('');
      final bytes = base64Decode(base64.normalize(input));
      json = jsonDecode(utf8.decode(bytes));
    }
    idServer = json['host'] ?? '';
    relayServer = json['relay'] ?? '';
    apiServer = json['api'] ?? '';
    key = json['key'] ?? '';
  }

  /// encode to shared string
  /// also see [ServerConfig.decode]
  String encode() {
    Map<String, String> config = {};
    config['host'] = idServer.trim();
    config['relay'] = relayServer.trim();
    config['api'] = apiServer.trim();
    config['key'] = key.trim();
    return base64Encode(Uint8List.fromList(jsonEncode(config).codeUnits))
        .split('')
        .reversed
        .join();
  }

  /// from local options
  ServerConfig.fromOptions(Map<String, dynamic> options)
      : idServer = options['custom-rendezvous-server'] ?? "",
        relayServer = options['relay-server'] ?? "",
        apiServer = options['api-server'] ?? "",
        key = options['key'] ?? "";
}

Widget dialogButton(String text,
    {required VoidCallback? onPressed,
    bool isOutline = false,
    Widget? icon,
    TextStyle? style,
    ButtonStyle? buttonStyle}) {
  if (isDesktop) {
    if (isOutline) {
      return icon == null
          ? OutlinedButton(
              onPressed: onPressed,
              child: Text(translate(text), style: style),
            )
          : OutlinedButton.icon(
              icon: icon,
              onPressed: onPressed,
              label: Text(translate(text), style: style),
            );
    } else {
      return icon == null
          ? ElevatedButton(
              style: ElevatedButton.styleFrom(elevation: 0).merge(buttonStyle),
              onPressed: onPressed,
              child: Text(translate(text), style: style),
            )
          : ElevatedButton.icon(
              icon: icon,
              style: ElevatedButton.styleFrom(elevation: 0).merge(buttonStyle),
              onPressed: onPressed,
              label: Text(translate(text), style: style),
            );
    }
  } else {
    return TextButton(
      onPressed: onPressed,
      child: Text(
        translate(text),
        style: style,
      ),
    );
  }
}

int versionCmp(String v1, String v2) {
  return bind.versionToNumber(v: v1) - bind.versionToNumber(v: v2);
}

String getWindowName({WindowType? overrideType}) {
  switch (overrideType ?? kWindowType) {
    case WindowType.Main:
      return "RustDesk";
    case WindowType.FileTransfer:
      return "File Transfer - RustDesk";
    case WindowType.PortForward:
      return "Port Forward - RustDesk";
    case WindowType.RemoteDesktop:
      return "Remote Desktop - RustDesk";
    default:
      break;
  }
  return "RustDesk";
}

String getWindowNameWithId(String id, {WindowType? overrideType}) {
  return "${DesktopTab.tablabelGetter(id).value} - ${getWindowName(overrideType: overrideType)}";
}

Future<void> updateSystemWindowTheme() async {
  // Set system window theme for macOS.
  final userPreference = MyTheme.getThemeModePreference();
  if (userPreference != ThemeMode.system) {
    if (Platform.isMacOS) {
      await RdPlatformChannel.instance.changeSystemWindowTheme(
          userPreference == ThemeMode.light
              ? SystemWindowTheme.light
              : SystemWindowTheme.dark);
    }
  }
}

/// macOS only
///
/// Note: not found a general solution for rust based AVFoundation bingding.
/// [AVFoundation] crate has compile error.
const kMacOSPermChannel = MethodChannel("org.rustdesk.rustdesk/macos");

enum PermissionAuthorizeType {
  undetermined,
  authorized,
  denied, // and restricted
}

Future<PermissionAuthorizeType> osxCanRecordAudio() async {
  int res = await kMacOSPermChannel.invokeMethod("canRecordAudio");
  print(res);
  if (res > 0) {
    return PermissionAuthorizeType.authorized;
  } else if (res == 0) {
    return PermissionAuthorizeType.undetermined;
  } else {
    return PermissionAuthorizeType.denied;
  }
}

Future<bool> osxRequestAudio() async {
  return await kMacOSPermChannel.invokeMethod("requestRecordAudio");
}

class DraggableNeverScrollableScrollPhysics extends ScrollPhysics {
  /// Creates scroll physics that does not let the user scroll.
  const DraggableNeverScrollableScrollPhysics({super.parent});

  @override
  DraggableNeverScrollableScrollPhysics applyTo(ScrollPhysics? ancestor) {
    return DraggableNeverScrollableScrollPhysics(parent: buildParent(ancestor));
  }

  @override
  bool shouldAcceptUserOffset(ScrollMetrics position) {
    // TODO: find a better solution to check if the offset change is caused by the scrollbar.
    // Workaround: when dragging with the scrollbar, it always triggers an [IdleScrollActivity].
    if (position is ScrollPositionWithSingleContext) {
      // ignore: invalid_use_of_protected_member, invalid_use_of_visible_for_testing_member
      return position.activity is IdleScrollActivity;
    }
    return false;
  }

  @override
  bool get allowImplicitScrolling => false;
}

Widget futureBuilder(
    {required Future? future, required Widget Function(dynamic data) hasData}) {
  return FutureBuilder(
      future: future,
      builder: (BuildContext context, AsyncSnapshot snapshot) {
        if (snapshot.hasData) {
          return hasData(snapshot.data!);
        } else {
          if (snapshot.hasError) {
            debugPrint(snapshot.error.toString());
          }
          return Container();
        }
      });
}

void onCopyFingerprint(String value) {
  if (value.isNotEmpty) {
    Clipboard.setData(ClipboardData(text: value));
    showToast('$value\n${translate("Copied")}');
  } else {
    showToast(translate("no fingerprints"));
  }
}

Future<bool> callMainCheckSuperUserPermission() async {
  bool checked = await bind.mainCheckSuperUserPermission();
  if (Platform.isMacOS) {
    await windowManager.show();
  }
  return checked;
}

Future<void> start_service(bool is_start) async {
  bool checked = !bind.mainIsInstalled() ||
      !Platform.isMacOS ||
      await callMainCheckSuperUserPermission();
  if (checked) {
    bind.mainSetOption(key: "stop-service", value: is_start ? "" : "Y");
  }
}

typedef Future<bool> WhetherUseRemoteBlock();
Widget buildRemoteBlock({required Widget child, WhetherUseRemoteBlock? use}) {
  var block = false.obs;
  return Obx(() => MouseRegion(
        onEnter: (_) async {
          if (use != null && !await use()) {
            block.value = false;
            return;
          }
          var time0 = DateTime.now().millisecondsSinceEpoch;
          await bind.mainCheckMouseTime();
          Timer(const Duration(milliseconds: 120), () async {
            var d = time0 - await bind.mainGetMouseTime();
            if (d < 120) {
              block.value = true;
            }
          });
        },
        onExit: (event) => block.value = false,
        child: Stack(children: [
          child,
          Offstage(
              offstage: !block.value,
              child: Container(
                color: Colors.black.withOpacity(0.5),
              )),
        ]),
      ));
}

Widget unreadMessageCountBuilder(RxInt? count,
    {double? size, double? fontSize}) {
  return Obx(() => Offstage(
      offstage: !((count?.value ?? 0) > 0),
      child: Container(
        width: size ?? 16,
        height: size ?? 16,
        decoration: BoxDecoration(
          color: Colors.red,
          shape: BoxShape.circle,
        ),
        child: Center(
          child: Text("${count?.value ?? 0}",
              maxLines: 1,
              style: TextStyle(color: Colors.white, fontSize: fontSize ?? 10)),
        ),
      )));
}

Widget unreadTopRightBuilder(RxInt? count, {Widget? icon}) {
  return Stack(
    children: [
      icon ?? Icon(Icons.chat),
      Positioned(
          top: 0,
          right: 0,
          child: unreadMessageCountBuilder(count, size: 12, fontSize: 8))
    ],
  );
}

String toCapitalized(String s) {
  if (s.isEmpty) {
    return s;
  }
  return s.substring(0, 1).toUpperCase() + s.substring(1);
}

Widget buildErrorBanner(BuildContext context,
    {required RxBool loading,
    required RxString err,
    required Function? retry,
    required Function close}) {
  const double height = 25;
  return Obx(() => Offstage(
        offstage: !(!loading.value && err.value.isNotEmpty),
        child: Center(
            child: Container(
          height: height,
          color: MyTheme.color(context).errorBannerBg,
          child: Row(
            mainAxisAlignment: MainAxisAlignment.center,
            crossAxisAlignment: CrossAxisAlignment.center,
            children: [
              FittedBox(
                child: Icon(
                  Icons.info,
                  color: Color.fromARGB(255, 249, 81, 81),
                ),
              ).marginAll(4),
              Flexible(
                child: Align(
                    alignment: Alignment.centerLeft,
                    child: Tooltip(
                      message: translate(err.value),
                      child: Text(
                        translate(err.value),
                        overflow: TextOverflow.ellipsis,
                      ),
                    )).marginSymmetric(vertical: 2),
              ),
              if (retry != null)
                InkWell(
                    onTap: () {
                      retry.call();
                    },
                    child: Text(
                      translate("Retry"),
                      style: TextStyle(color: MyTheme.accent),
                    )).marginSymmetric(horizontal: 5),
              FittedBox(
                child: InkWell(
                  onTap: () {
                    close.call();
                  },
                  child: Icon(Icons.close).marginSymmetric(horizontal: 5),
                ),
              ).marginAll(4)
            ],
          ),
        )).marginOnly(bottom: 14),
      ));
}

String getDesktopTabLabel(String peerId, String alias) {
  String label = alias.isEmpty ? peerId : alias;
  try {
    String peer = bind.mainGetPeerSync(id: peerId);
    Map<String, dynamic> config = jsonDecode(peer);
    if (config['info']['hostname'] is String) {
      String hostname = config['info']['hostname'];
      if (hostname.isNotEmpty &&
          !label.toLowerCase().contains(hostname.toLowerCase())) {
        label += "@$hostname";
      }
    }
  } catch (e) {
    debugPrint("Failed to get hostname:$e");
  }
  return label;
}

sessionRefreshVideo(SessionID sessionId, PeerInfo pi) async {
  if (pi.currentDisplay == kAllDisplayValue) {
    for (int i = 0; i < pi.displays.length; i++) {
      await bind.sessionRefresh(sessionId: sessionId, display: i);
    }
  } else {
    await bind.sessionRefresh(sessionId: sessionId, display: pi.currentDisplay);
  }
}

bool isChooseDisplayToOpenInNewWindow(PeerInfo pi, SessionID sessionId) =>
    pi.isSupportMultiDisplay &&
    useTextureRender &&
    bind.sessionGetDisplaysAsIndividualWindows(sessionId: sessionId) == 'Y';

Future<List<Rect>> getScreenListWayland() async {
  final screenRectList = <Rect>[];
  if (isMainDesktopWindow) {
    for (var screen in await window_size.getScreenList()) {
      final scale = kIgnoreDpi ? 1.0 : screen.scaleFactor;
      double l = screen.frame.left;
      double t = screen.frame.top;
      double r = screen.frame.right;
      double b = screen.frame.bottom;
      final rect = Rect.fromLTRB(l / scale, t / scale, r / scale, b / scale);
      screenRectList.add(rect);
    }
  } else {
    final screenList = await rustDeskWinManager.call(
        WindowType.Main, kWindowGetScreenList, '');
    try {
      for (var screen in jsonDecode(screenList.result) as List<dynamic>) {
        final scale = kIgnoreDpi ? 1.0 : screen['scaleFactor'];
        double l = screen['frame']['l'];
        double t = screen['frame']['t'];
        double r = screen['frame']['r'];
        double b = screen['frame']['b'];
        final rect = Rect.fromLTRB(l / scale, t / scale, r / scale, b / scale);
        screenRectList.add(rect);
      }
    } catch (e) {
      debugPrint('Failed to parse screenList: $e');
    }
  }
  return screenRectList;
}

Future<List<Rect>> getScreenListNotWayland() async {
  final screenRectList = <Rect>[];
  final displays = bind.mainGetDisplays();
  if (displays.isEmpty) {
    return screenRectList;
  }
  try {
    for (var display in jsonDecode(displays) as List<dynamic>) {
      // to-do: scale factor ?
      // final scale = kIgnoreDpi ? 1.0 : screen.scaleFactor;
      double l = display['x'].toDouble();
      double t = display['y'].toDouble();
      double r = (display['x'] + display['w']).toDouble();
      double b = (display['y'] + display['h']).toDouble();
      screenRectList.add(Rect.fromLTRB(l, t, r, b));
    }
  } catch (e) {
    debugPrint('Failed to parse displays: $e');
  }
  return screenRectList;
}

Future<List<Rect>> getScreenRectList() async {
  return bind.mainCurrentIsWayland()
      ? await getScreenListWayland()
      : await getScreenListNotWayland();
}

openMonitorInTheSameTab(int i, FFI ffi, PeerInfo pi) {
  final displays = i == kAllDisplayValue
      ? List.generate(pi.displays.length, (index) => index)
      : [i];
  bind.sessionSwitchDisplay(
      sessionId: ffi.sessionId, value: Int32List.fromList(displays));
  ffi.ffiModel.switchToNewDisplay(i, ffi.sessionId, ffi.id);
}

// Open new tab or window to show this monitor.
// For now just open new window.
//
// screenRect is used to move the new window to the specified screen and set fullscreen.
openMonitorInNewTabOrWindow(int i, String peerId, PeerInfo pi,
    {Rect? screenRect}) {
  final args = {
    'window_id': stateGlobal.windowId,
    'peer_id': peerId,
    'display': i,
    'display_count': pi.displays.length,
  };
  if (screenRect != null) {
    args['screen_rect'] = {
      'l': screenRect.left,
      't': screenRect.top,
      'r': screenRect.right,
      'b': screenRect.bottom,
    };
  }
  DesktopMultiWindow.invokeMethod(
      kMainWindowId, kWindowEventOpenMonitorSession, jsonEncode(args));
}

tryMoveToScreenAndSetFullscreen(Rect? screenRect) async {
  if (screenRect == null) {
    return;
  }
  final wc = WindowController.fromWindowId(stateGlobal.windowId);
  final curFrame = await wc.getFrame();
  final frame =
      Rect.fromLTWH(screenRect.left + 30, screenRect.top + 30, 600, 400);
  if (stateGlobal.fullscreen.isTrue &&
      curFrame.left <= frame.left &&
      curFrame.top <= frame.top &&
      curFrame.width >= frame.width &&
      curFrame.height >= frame.height) {
    return;
  }
  await wc.setFrame(frame);
  // An duration is needed to avoid the window being restored after fullscreen.
  Future.delayed(Duration(milliseconds: 300), () async {
    stateGlobal.setFullscreen(true);
  });
}

parseParamScreenRect(Map<String, dynamic> params) {
  Rect? screenRect;
  if (params['screen_rect'] != null) {
    double l = params['screen_rect']['l'];
    double t = params['screen_rect']['t'];
    double r = params['screen_rect']['r'];
    double b = params['screen_rect']['b'];
    screenRect = Rect.fromLTRB(l, t, r, b);
  }
  return screenRect;
}

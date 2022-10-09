import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/models/chat_model.dart';
import 'package:get/get.dart';
import 'package:provider/provider.dart';
import 'package:rxdart/rxdart.dart' as rxdart;

import '../../common.dart';
import '../../mobile/widgets/dialog.dart';
import '../../models/model.dart';
import '../../models/platform_model.dart';
import '../../common/shared_state.dart';
import './popup_menu.dart';
import './material_mod_popup_menu.dart' as mod_menu;

class _MenubarTheme {
  static const Color commonColor = MyTheme.accent;
  // kMinInteractiveDimension
  static const double height = 20.0;
  static const double dividerHeight = 12.0;
}

class RemoteMenubar extends StatefulWidget {
  final String id;
  final FFI ffi;
  final Function(Function(bool)) onEnterOrLeaveImageSetter;
  final Function() onEnterOrLeaveImageCleaner;

  const RemoteMenubar({
    Key? key,
    required this.id,
    required this.ffi,
    required this.onEnterOrLeaveImageSetter,
    required this.onEnterOrLeaveImageCleaner,
  }) : super(key: key);

  @override
  State<RemoteMenubar> createState() => _RemoteMenubarState();
}

class _RemoteMenubarState extends State<RemoteMenubar> {
  final RxBool _show = false.obs;
  final Rx<Color> _hideColor = Colors.white12.obs;
  final _rxHideReplay = rxdart.ReplaySubject<int>();
  final _pinMenubar = false.obs;
  bool _isCursorOverImage = false;

  bool get isFullscreen => Get.find<RxBool>(tag: 'fullscreen').isTrue;
  void _setFullscreen(bool v) {
    Get.find<RxBool>(tag: 'fullscreen').value = v;
  }

  @override
  initState() {
    super.initState();

    widget.onEnterOrLeaveImageSetter((enter) {
      if (enter) {
        _rxHideReplay.add(0);
        _isCursorOverImage = true;
      } else {
        _isCursorOverImage = false;
      }
    });

    _rxHideReplay
        .throttleTime(const Duration(milliseconds: 5000),
            trailing: true, leading: false)
        .listen((int v) {
      if (_pinMenubar.isFalse && _show.isTrue && _isCursorOverImage) {
        _show.value = false;
      }
    });
  }

  @override
  dispose() {
    super.dispose();

    widget.onEnterOrLeaveImageCleaner();
  }

  @override
  Widget build(BuildContext context) {
    return Align(
      alignment: Alignment.topCenter,
      child: Obx(
          () => _show.value ? _buildMenubar(context) : _buildShowHide(context)),
    );
  }

  Widget _buildShowHide(BuildContext context) {
    return Obx(() => Tooltip(
        message: translate(_show.value ? "Hide Menubar" : "Show Menubar"),
        child: SizedBox(
            width: 100,
            height: 13,
            child: TextButton(
                onHover: (bool v) {
                  _hideColor.value = v ? Colors.white60 : Colors.white24;
                },
                onPressed: () {
                  _show.value = !_show.value;
                },
                child: Obx(() => Container(
                      color: _hideColor.value,
                    ).marginOnly(bottom: 8.0))))));
  }

  Widget _buildMenubar(BuildContext context) {
    final List<Widget> menubarItems = [];
    if (!isWebDesktop) {
      menubarItems.add(_buildPinMenubar(context));
      menubarItems.add(_buildFullscreen(context));
      if (widget.ffi.ffiModel.isPeerAndroid) {
        menubarItems.add(IconButton(
          tooltip: translate('Mobile Actions'),
          color: _MenubarTheme.commonColor,
          icon: const Icon(Icons.build),
          onPressed: () {
            widget.ffi.dialogManager
                .toggleMobileActionsOverlay(ffi: widget.ffi);
          },
        ));
      }
    }
    menubarItems.add(_buildMonitor(context));
    menubarItems.add(_buildControl(context));
    menubarItems.add(_buildDisplay(context));
    menubarItems.add(_buildKeyboard(context));
    if (!isWeb) {
      menubarItems.add(_buildChat(context));
    }
    menubarItems.add(_buildRecording(context));
    menubarItems.add(_buildClose(context));
    return PopupMenuTheme(
        data: const PopupMenuThemeData(
            textStyle: TextStyle(color: _MenubarTheme.commonColor)),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          Container(
              color: Colors.white,
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: menubarItems,
              )),
          _buildShowHide(context),
        ]));
  }

  Widget _buildPinMenubar(BuildContext context) {
    return Obx(() => IconButton(
          tooltip:
              translate(_pinMenubar.isTrue ? 'Unpin menubar' : 'Pin menubar'),
          onPressed: () {
            _pinMenubar.value = !_pinMenubar.value;
          },
          icon: Obx(() => Transform.rotate(
              angle: _pinMenubar.isTrue ? math.pi / 4 : 0,
              child: Icon(
                Icons.push_pin,
                color: _pinMenubar.isTrue
                    ? _MenubarTheme.commonColor
                    : Colors.grey,
              ))),
        ));
  }

  Widget _buildFullscreen(BuildContext context) {
    return IconButton(
      tooltip: translate(isFullscreen ? 'Exit Fullscreen' : 'Fullscreen'),
      onPressed: () {
        _setFullscreen(!isFullscreen);
      },
      icon: Obx(() => isFullscreen
          ? const Icon(
              Icons.fullscreen_exit,
              color: _MenubarTheme.commonColor,
            )
          : const Icon(
              Icons.fullscreen,
              color: _MenubarTheme.commonColor,
            )),
    );
  }

  Widget _buildChat(BuildContext context) {
    return IconButton(
      tooltip: translate('Chat'),
      onPressed: () {
        widget.ffi.chatModel.changeCurrentID(ChatModel.clientModeID);
        widget.ffi.chatModel.toggleChatOverlay();
      },
      icon: const Icon(
        Icons.message,
        color: _MenubarTheme.commonColor,
      ),
    );
  }

  Widget _buildMonitor(BuildContext context) {
    final pi = widget.ffi.ffiModel.pi;
    return mod_menu.PopupMenuButton(
      tooltip: translate('Select Monitor'),
      padding: EdgeInsets.zero,
      position: mod_menu.PopupMenuPosition.under,
      icon: Stack(
        alignment: Alignment.center,
        children: [
          const Icon(
            Icons.personal_video,
            color: _MenubarTheme.commonColor,
          ),
          Padding(
            padding: const EdgeInsets.only(bottom: 3.9),
            child: Obx(() {
              RxInt display = CurrentDisplayState.find(widget.id);
              return Text(
                "${display.value + 1}/${pi.displays.length}",
                style: const TextStyle(
                    color: _MenubarTheme.commonColor, fontSize: 8),
              );
            }),
          )
        ],
      ),
      itemBuilder: (BuildContext context) {
        final List<Widget> rowChildren = [];
        for (int i = 0; i < pi.displays.length; i++) {
          rowChildren.add(
            Stack(
              alignment: Alignment.center,
              children: [
                const Icon(
                  Icons.personal_video,
                  color: _MenubarTheme.commonColor,
                ),
                TextButton(
                  child: Container(
                      alignment: AlignmentDirectional.center,
                      constraints:
                          const BoxConstraints(minHeight: _MenubarTheme.height),
                      child: Padding(
                        padding: const EdgeInsets.only(bottom: 2.5),
                        child: Text(
                          (i + 1).toString(),
                          style:
                              const TextStyle(color: _MenubarTheme.commonColor),
                        ),
                      )),
                  onPressed: () {
                    RxInt display = CurrentDisplayState.find(widget.id);
                    if (display.value != i) {
                      bind.sessionSwitchDisplay(id: widget.id, value: i);
                      pi.currentDisplay = i;
                      display.value = i;
                    }
                  },
                )
              ],
            ),
          );
        }
        return <mod_menu.PopupMenuEntry<String>>[
          mod_menu.PopupMenuItem<String>(
            height: _MenubarTheme.height,
            padding: EdgeInsets.zero,
            child: Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: rowChildren),
          )
        ];
      },
    );
  }

  Widget _buildControl(BuildContext context) {
    return mod_menu.PopupMenuButton(
      padding: EdgeInsets.zero,
      icon: const Icon(
        Icons.bolt,
        color: _MenubarTheme.commonColor,
      ),
      tooltip: translate('Control Actions'),
      position: mod_menu.PopupMenuPosition.under,
      itemBuilder: (BuildContext context) => _getControlMenu(context)
          .map((entry) => entry.build(
              context,
              const MenuConfig(
                commonColor: _MenubarTheme.commonColor,
                height: _MenubarTheme.height,
                dividerHeight: _MenubarTheme.dividerHeight,
              )))
          .expand((i) => i)
          .toList(),
    );
  }

  Widget _buildDisplay(BuildContext context) {
    return FutureBuilder(future: () async {
      final supportedHwcodec =
          await bind.sessionSupportedHwcodec(id: widget.id);
      return {'supportedHwcodec': supportedHwcodec};
    }(), builder: (context, snapshot) {
      if (snapshot.hasData) {
        return mod_menu.PopupMenuButton(
          padding: EdgeInsets.zero,
          icon: const Icon(
            Icons.tv,
            color: _MenubarTheme.commonColor,
          ),
          tooltip: translate('Display Settings'),
          position: mod_menu.PopupMenuPosition.under,
          itemBuilder: (BuildContext context) => _getDisplayMenu(snapshot.data!)
              .map((entry) => entry.build(
                  context,
                  const MenuConfig(
                    commonColor: _MenubarTheme.commonColor,
                    height: _MenubarTheme.height,
                    dividerHeight: _MenubarTheme.dividerHeight,
                  )))
              .expand((i) => i)
              .toList(),
        );
      } else {
        return const Offstage();
      }
    });
  }

  Widget _buildKeyboard(BuildContext context) {
    return mod_menu.PopupMenuButton(
      padding: EdgeInsets.zero,
      icon: const Icon(
        Icons.keyboard,
        color: _MenubarTheme.commonColor,
      ),
      tooltip: translate('Keyboard Settings'),
      position: mod_menu.PopupMenuPosition.under,
      itemBuilder: (BuildContext context) => _getKeyboardMenu()
          .map((entry) => entry.build(
              context,
              const MenuConfig(
                commonColor: _MenubarTheme.commonColor,
                height: _MenubarTheme.height,
                dividerHeight: _MenubarTheme.dividerHeight,
              )))
          .expand((i) => i)
          .toList(),
    );
  }

  Widget _buildRecording(BuildContext context) {
    return Consumer<FfiModel>(builder: ((context, value, child) {
      if (value.permissions['recording'] != false) {
        return Consumer<RecordingModel>(
            builder: (context, value, child) => IconButton(
                  tooltip: value.start
                      ? translate('Stop session recording')
                      : translate('Start session recording'),
                  onPressed: () => value.toggle(),
                  icon: Icon(
                    value.start
                        ? Icons.pause_circle_filled
                        : Icons.videocam_outlined,
                    color: _MenubarTheme.commonColor,
                  ),
                ));
      } else {
        return Offstage();
      }
    }));
  }

  Widget _buildClose(BuildContext context) {
    return IconButton(
      tooltip: translate('Close'),
      onPressed: () {
        clientClose(widget.ffi.dialogManager);
      },
      icon: const Icon(
        Icons.close,
        color: _MenubarTheme.commonColor,
      ),
    );
  }

  List<MenuEntryBase<String>> _getControlMenu(BuildContext context) {
    final pi = widget.ffi.ffiModel.pi;
    final perms = widget.ffi.ffiModel.permissions;
    const EdgeInsets padding = EdgeInsets.only(left: 14.0, right: 5.0);
    final List<MenuEntryBase<String>> displayMenu = [];
    displayMenu.addAll([
      MenuEntryButton<String>(
        childBuilder: (TextStyle? style) => Container(
            alignment: AlignmentDirectional.center,
            height: _MenubarTheme.height,
            child: Row(
              children: [
                Text(
                  translate('OS Password'),
                  style: style,
                ),
                Expanded(
                    child: Align(
                  alignment: Alignment.centerRight,
                  child: Transform.scale(
                      scale: 0.8,
                      child: IconButton(
                          padding: EdgeInsets.zero,
                          icon: const Icon(Icons.edit),
                          onPressed: () {
                            if (Navigator.canPop(context)) {
                              Navigator.pop(context);
                            }
                            showSetOSPassword(
                                widget.id, false, widget.ffi.dialogManager);
                          })),
                ))
              ],
            )),
        proc: () {
          showSetOSPassword(widget.id, false, widget.ffi.dialogManager);
        },
        padding: padding,
        dismissOnClicked: true,
      ),
      MenuEntryButton<String>(
        childBuilder: (TextStyle? style) => Text(
          translate('Transfer File'),
          style: style,
        ),
        proc: () {
          connect(context, widget.id, isFileTransfer: true);
        },
        padding: padding,
        dismissOnClicked: true,
      ),
      MenuEntryButton<String>(
        childBuilder: (TextStyle? style) => Text(
          translate('TCP Tunneling'),
          style: style,
        ),
        padding: padding,
        proc: () {
          connect(context, widget.id, isTcpTunneling: true);
        },
        dismissOnClicked: true,
      ),
    ]);
    // {handler.get_audit_server() && <li #note>{translate('Note')}</li>}
    final auditServer = bind.sessionGetAuditServerSync(id: widget.id);
    if (auditServer.isNotEmpty) {
      displayMenu.add(
        MenuEntryButton<String>(
          childBuilder: (TextStyle? style) => Text(
            translate('Note'),
            style: style,
          ),
          proc: () {
            showAuditDialog(widget.id, widget.ffi.dialogManager);
          },
          padding: padding,
          dismissOnClicked: true,
        ),
      );
    }
    displayMenu.add(MenuEntryDivider());

    if (perms['keyboard'] != false) {
      if (pi.platform == 'Linux' || pi.sasEnabled) {
        displayMenu.add(MenuEntryButton<String>(
          childBuilder: (TextStyle? style) => Text(
            '${translate("Insert")} Ctrl + Alt + Del',
            style: style,
          ),
          proc: () {
            bind.sessionCtrlAltDel(id: widget.id);
          },
          padding: padding,
          dismissOnClicked: true,
        ));
      }
    }
    if (gFFI.ffiModel.permissions["restart"] != false &&
        (pi.platform == "Linux" ||
            pi.platform == "Windows" ||
            pi.platform == "Mac OS")) {
      displayMenu.add(MenuEntryButton<String>(
        childBuilder: (TextStyle? style) => Text(
          translate('Restart Remote Device'),
          style: style,
        ),
        proc: () {
          showRestartRemoteDevice(pi, widget.id, gFFI.dialogManager);
        },
        padding: padding,
        dismissOnClicked: true,
      ));
    }

    if (perms['keyboard'] != false) {
      displayMenu.add(MenuEntryButton<String>(
        childBuilder: (TextStyle? style) => Text(
          translate('Insert Lock'),
          style: style,
        ),
        proc: () {
          bind.sessionLockScreen(id: widget.id);
        },
        padding: padding,
        dismissOnClicked: true,
      ));

      if (pi.platform == 'Windows') {
        displayMenu.add(MenuEntryButton<String>(
          childBuilder: (TextStyle? style) => Obx(() => Text(
                translate(
                    '${BlockInputState.find(widget.id).value ? "Unb" : "B"}lock user input'),
                style: style,
              )),
          proc: () {
            RxBool blockInput = BlockInputState.find(widget.id);
            bind.sessionToggleOption(
                id: widget.id,
                value: '${blockInput.value ? "un" : ""}block-input');
            blockInput.value = !blockInput.value;
          },
          padding: padding,
          dismissOnClicked: true,
        ));
      }
    }

    if (pi.version.isNotEmpty) {
      displayMenu.add(MenuEntryButton<String>(
        childBuilder: (TextStyle? style) => Text(
          translate('Refresh'),
          style: style,
        ),
        proc: () {
          bind.sessionRefresh(id: widget.id);
        },
        padding: padding,
        dismissOnClicked: true,
      ));
    }

    if (!isWebDesktop) {
      //   if (perms['keyboard'] != false && perms['clipboard'] != false) {
      //     displayMenu.add(MenuEntryButton<String>(
      //       childBuilder: (TextStyle? style) => Text(
      //         translate('Paste'),
      //         style: style,
      //       ),
      //       proc: () {
      //         () async {
      //           ClipboardData? data =
      //               await Clipboard.getData(Clipboard.kTextPlain);
      //           if (data != null && data.text != null) {
      //             bind.sessionInputString(id: widget.id, value: data.text ?? "");
      //           }
      //         }();
      //       },
      //       padding: padding,
      //       dismissOnClicked: true,
      //     ));
      //   }

      displayMenu.add(MenuEntryButton<String>(
        childBuilder: (TextStyle? style) => Text(
          translate('Reset canvas'),
          style: style,
        ),
        proc: () {
          widget.ffi.cursorModel.reset();
        },
        padding: padding,
        dismissOnClicked: true,
      ));
    }

    return displayMenu;
  }

  List<MenuEntryBase<String>> _getDisplayMenu(dynamic futureData) {
    const EdgeInsets padding = EdgeInsets.only(left: 18.0, right: 8.0);
    final displayMenu = [
      MenuEntryRadios<String>(
        text: translate('Ratio'),
        optionsGetter: () => [
          MenuEntryRadioOption(
            text: translate('Scale original'),
            value: 'original',
            dismissOnClicked: true,
          ),
          MenuEntryRadioOption(
            text: translate('Scale adaptive'),
            value: 'adaptive',
            dismissOnClicked: true,
          ),
        ],
        curOptionGetter: () async {
          return await bind.sessionGetOption(
                  id: widget.id, arg: 'view-style') ??
              'adaptive';
        },
        optionSetter: (String oldValue, String newValue) async {
          await bind.sessionPeerOption(
              id: widget.id, name: "view-style", value: newValue);
          widget.ffi.canvasModel.updateViewStyle();
        },
        padding: padding,
        dismissOnClicked: true,
      ),
      MenuEntryDivider<String>(),
      MenuEntryRadios<String>(
        text: translate('Scroll Style'),
        optionsGetter: () => [
          MenuEntryRadioOption(
            text: translate('ScrollAuto'),
            value: 'scrollauto',
            dismissOnClicked: true,
          ),
          MenuEntryRadioOption(
            text: translate('Scrollbar'),
            value: 'scrollbar',
            dismissOnClicked: true,
          ),
        ],
        curOptionGetter: () async {
          return await bind.sessionGetOption(
                  id: widget.id, arg: 'scroll-style') ??
              '';
        },
        optionSetter: (String oldValue, String newValue) async {
          await bind.sessionPeerOption(
              id: widget.id, name: "scroll-style", value: newValue);
          widget.ffi.canvasModel.updateScrollStyle();
        },
        padding: padding,
        dismissOnClicked: true,
      ),
      MenuEntryDivider<String>(),
      MenuEntryRadios<String>(
        text: translate('Image Quality'),
        optionsGetter: () => [
          MenuEntryRadioOption(
            text: translate('Good image quality'),
            value: 'best',
            dismissOnClicked: true,
          ),
          MenuEntryRadioOption(
            text: translate('Balanced'),
            value: 'balanced',
            dismissOnClicked: true,
          ),
          MenuEntryRadioOption(
            text: translate('Optimize reaction time'),
            value: 'low',
            dismissOnClicked: true,
          ),
          MenuEntryRadioOption(
              text: translate('Custom'),
              value: 'custom',
              dismissOnClicked: true),
        ],
        curOptionGetter: () async {
          String quality =
              await bind.sessionGetImageQuality(id: widget.id) ?? 'balanced';
          if (quality == '') quality = 'balanced';
          return quality;
        },
        optionSetter: (String oldValue, String newValue) async {
          if (oldValue != newValue) {
            await bind.sessionSetImageQuality(id: widget.id, value: newValue);
          }

          if (newValue == 'custom') {
            final btnCancel = msgBoxButton(translate('Close'), () {
              widget.ffi.dialogManager.dismissAll();
            });
            final quality =
                await bind.sessionGetCustomImageQuality(id: widget.id);
            double initValue = quality != null && quality.isNotEmpty
                ? quality[0].toDouble()
                : 50.0;
            const minValue = 10.0;
            const maxValue = 100.0;
            if (initValue < minValue) {
              initValue = minValue;
            }
            if (initValue > maxValue) {
              initValue = maxValue;
            }
            final RxDouble sliderValue = RxDouble(initValue);
            final rxReplay = rxdart.ReplaySubject<double>();
            rxReplay
                .throttleTime(const Duration(milliseconds: 1000),
                    trailing: true, leading: false)
                .listen((double v) {
              () async {
                await bind.sessionSetCustomImageQuality(
                    id: widget.id, value: v.toInt());
              }();
            });
            final slider = Obx(() {
              return Slider(
                value: sliderValue.value,
                min: minValue,
                max: maxValue,
                divisions: 90,
                onChanged: (double value) {
                  sliderValue.value = value;
                  rxReplay.add(value);
                },
              );
            });
            final content = Row(
              children: [
                slider,
                SizedBox(
                    width: 90,
                    child: Obx(() => Text(
                          '${sliderValue.value.round()}% Bitrate',
                          style: const TextStyle(fontSize: 15),
                        )))
              ],
            );
            msgBoxCommon(widget.ffi.dialogManager, 'Custom Image Quality',
                content, [btnCancel]);
          }
        },
        padding: padding,
      ),
      MenuEntryDivider<String>(),
    ];

    /// Show Codec Preference
    if (bind.mainHasHwcodec()) {
      final List<bool> codecs = [];
      try {
        final Map codecsJson = jsonDecode(futureData['supportedHwcodec']);
        final h264 = codecsJson['h264'] ?? false;
        final h265 = codecsJson['h265'] ?? false;
        codecs.add(h264);
        codecs.add(h265);
      } finally {}
      if (codecs.length == 2 && (codecs[0] || codecs[1])) {
        displayMenu.add(MenuEntryRadios<String>(
          text: translate('Codec Preference'),
          optionsGetter: () {
            final list = [
              MenuEntryRadioOption(
                text: translate('Auto'),
                value: 'auto',
                dismissOnClicked: true,
              ),
              MenuEntryRadioOption(
                text: 'VP9',
                value: 'vp9',
                dismissOnClicked: true,
              ),
            ];
            if (codecs[0]) {
              list.add(MenuEntryRadioOption(
                text: 'H264',
                value: 'h264',
                dismissOnClicked: true,
              ));
            }
            if (codecs[1]) {
              list.add(MenuEntryRadioOption(
                text: 'H265',
                value: 'h265',
                dismissOnClicked: true,
              ));
            }
            return list;
          },
          curOptionGetter: () async {
            return await bind.sessionGetOption(
                    id: widget.id, arg: 'codec-preference') ??
                'auto';
          },
          optionSetter: (String oldValue, String newValue) async {
            await bind.sessionPeerOption(
                id: widget.id, name: "codec-preference", value: newValue);
            bind.sessionChangePreferCodec(id: widget.id);
          },
          padding: padding,
          dismissOnClicked: true,
        ));
      }
    }

    /// Show remote cursor
    displayMenu.add(() {
      final state = ShowRemoteCursorState.find(widget.id);
      return MenuEntrySwitch2<String>(
        switchType: SwitchType.scheckbox,
        text: translate('Show remote cursor'),
        getter: () {
          return state;
        },
        setter: (bool v) async {
          state.value = v;
          await bind.sessionToggleOption(
              id: widget.id, value: 'show-remote-cursor');
        },
        padding: padding,
        dismissOnClicked: true,
      );
    }());

    /// Show quality monitor
    displayMenu.add(MenuEntrySwitch<String>(
      switchType: SwitchType.scheckbox,
      text: translate('Show quality monitor'),
      getter: () async {
        return bind.sessionGetToggleOptionSync(
            id: widget.id, arg: 'show-quality-monitor');
      },
      setter: (bool v) async {
        await bind.sessionToggleOption(
            id: widget.id, value: 'show-quality-monitor');
        widget.ffi.qualityMonitorModel.checkShowQualityMonitor(widget.id);
      },
      padding: padding,
      dismissOnClicked: true,
    ));

    final perms = widget.ffi.ffiModel.permissions;
    final pi = widget.ffi.ffiModel.pi;

    if (perms['audio'] != false) {
      displayMenu
          .add(_createSwitchMenuEntry('Mute', 'disable-audio', padding, true));
    }

    if (Platform.isWindows &&
        pi.platform == 'Windows' &&
        perms['file'] != false) {
      displayMenu.add(_createSwitchMenuEntry(
          'Allow file copy and paste', 'enable-file-transfer', padding, true));
    }

    if (perms['keyboard'] != false) {
      if (perms['clipboard'] != false) {
        displayMenu.add(_createSwitchMenuEntry(
            'Disable clipboard', 'disable-clipboard', padding, true));
      }
      displayMenu.add(_createSwitchMenuEntry(
          'Lock after session end', 'lock-after-session-end', padding, true));
      if (pi.platform == 'Windows') {
        displayMenu.add(MenuEntrySwitch2<String>(
          switchType: SwitchType.scheckbox,
          text: translate('Privacy mode'),
          getter: () {
            return PrivacyModeState.find(widget.id);
          },
          setter: (bool v) async {
            await bind.sessionToggleOption(
                id: widget.id, value: 'privacy-mode');
          },
          padding: padding,
          dismissOnClicked: true,
        ));
      }
    }
    return displayMenu;
  }

  List<MenuEntryBase<String>> _getKeyboardMenu() {
    final keyboardMenu = [
      MenuEntryRadios<String>(
        text: translate('Ratio'),
        optionsGetter: () => [
          MenuEntryRadioOption(text: translate('Legacy mode'), value: 'legacy'),
          MenuEntryRadioOption(text: translate('Map mode'), value: 'map'),
        ],
        curOptionGetter: () async {
          return await bind.sessionGetKeyboardName(id: widget.id);
        },
        optionSetter: (String oldValue, String newValue) async {
          await bind.sessionSetKeyboardMode(
              id: widget.id, keyboardMode: newValue);
          widget.ffi.canvasModel.updateViewStyle();
        },
      )
    ];

    return keyboardMenu;
  }

  MenuEntrySwitch<String> _createSwitchMenuEntry(
      String text, String option, EdgeInsets? padding, bool dismissOnClicked) {
    return MenuEntrySwitch<String>(
      switchType: SwitchType.scheckbox,
      text: translate(text),
      getter: () async {
        return bind.sessionGetToggleOptionSync(id: widget.id, arg: option);
      },
      setter: (bool v) async {
        await bind.sessionToggleOption(id: widget.id, value: option);
      },
      padding: padding,
      dismissOnClicked: dismissOnClicked,
    );
  }
}

void showSetOSPassword(
    String id, bool login, OverlayDialogManager dialogManager) async {
  final controller = TextEditingController();
  var password = await bind.sessionGetOption(id: id, arg: "os-password") ?? "";
  var autoLogin = await bind.sessionGetOption(id: id, arg: "auto-login") != "";
  controller.text = password;
  dialogManager.show((setState, close) {
    submit() {
      var text = controller.text.trim();
      bind.sessionPeerOption(id: id, name: "os-password", value: text);
      bind.sessionPeerOption(
          id: id, name: "auto-login", value: autoLogin ? 'Y' : '');
      if (text != "" && login) {
        bind.sessionInputOsPassword(id: id, value: text);
      }
      close();
    }

    return CustomAlertDialog(
      title: Text(translate('OS Password')),
      content: Column(mainAxisSize: MainAxisSize.min, children: [
        PasswordWidget(controller: controller),
        CheckboxListTile(
          contentPadding: const EdgeInsets.all(0),
          dense: true,
          controlAffinity: ListTileControlAffinity.leading,
          title: Text(
            translate('Auto Login'),
          ),
          value: autoLogin,
          onChanged: (v) {
            if (v == null) return;
            setState(() => autoLogin = v);
          },
        ),
      ]),
      actions: [
        TextButton(
          style: flatButtonStyle,
          onPressed: close,
          child: Text(translate('Cancel')),
        ),
        TextButton(
          style: flatButtonStyle,
          onPressed: submit,
          child: Text(translate('OK')),
        ),
      ],
      onSubmit: submit,
      onCancel: close,
    );
  });
}

void showAuditDialog(String id, dialogManager) async {
  final controller = TextEditingController();
  dialogManager.show((setState, close) {
    submit() {
      var text = controller.text.trim();
      if (text != "") {
        bind.sessionSendNote(id: id, note: text);
      }
      close();
    }

    late final focusNode = FocusNode(
      onKey: (FocusNode node, RawKeyEvent evt) {
        if (evt.logicalKey.keyLabel == 'Enter') {
          if (evt is RawKeyDownEvent) {
            int pos = controller.selection.base.offset;
            controller.text =
                '${controller.text.substring(0, pos)}\n${controller.text.substring(pos)}';
            controller.selection =
                TextSelection.fromPosition(TextPosition(offset: pos + 1));
          }
          return KeyEventResult.handled;
        }
        if (evt.logicalKey.keyLabel == 'Esc') {
          if (evt is RawKeyDownEvent) {
            close();
          }
          return KeyEventResult.handled;
        } else {
          return KeyEventResult.ignored;
        }
      },
    );

    return CustomAlertDialog(
      title: Text(translate('Note')),
      content: SizedBox(
          width: 250,
          height: 120,
          child: TextField(
            autofocus: true,
            keyboardType: TextInputType.multiline,
            textInputAction: TextInputAction.newline,
            decoration: const InputDecoration.collapsed(
              hintText: "input note here",
            ),
            // inputFormatters: [
            //   LengthLimitingTextInputFormatter(16),
            //   // FilteringTextInputFormatter(RegExp(r"[a-zA-z][a-zA-z0-9\_]*"), allow: true)
            // ],
            maxLines: null,
            maxLength: 256,
            controller: controller,
            focusNode: focusNode,
          )),
      actions: [
        TextButton(
          style: flatButtonStyle,
          onPressed: close,
          child: Text(translate('Cancel')),
        ),
        TextButton(
          style: flatButtonStyle,
          onPressed: submit,
          child: Text(translate('OK')),
        ),
      ],
      onSubmit: submit,
      onCancel: close,
    );
  });
}

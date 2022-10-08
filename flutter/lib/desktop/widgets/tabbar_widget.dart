import 'dart:io';
import 'dart:async';
import 'dart:math';

import 'package:desktop_multi_window/desktop_multi_window.dart';
import 'package:flutter/material.dart' hide TabBarTheme;
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/consts.dart';
import 'package:flutter_hbb/main.dart';
import 'package:flutter_hbb/models/platform_model.dart';
import 'package:get/get.dart';
import 'package:scroll_pos/scroll_pos.dart';
import 'package:window_manager/window_manager.dart';
import 'package:flutter_svg/flutter_svg.dart';

import '../../utils/multi_window_manager.dart';

const double _kTabBarHeight = kDesktopRemoteTabBarHeight;
const double _kIconSize = 18;
const double _kDividerIndent = 10;
const double _kActionIconSize = 12;

class TabInfo {
  final String key;
  final String label;
  final IconData? selectedIcon;
  final IconData? unselectedIcon;
  final bool closable;
  final VoidCallback? onTabCloseButton;
  final Widget page;

  TabInfo(
      {required this.key,
      required this.label,
      this.selectedIcon,
      this.unselectedIcon,
      this.closable = true,
      this.onTabCloseButton,
      required this.page});
}

enum DesktopTabType {
  main,
  cm,
  remoteScreen,
  fileTransfer,
  portForward,
}

class DesktopTabState {
  final List<TabInfo> tabs = [];
  final ScrollPosController scrollController =
      ScrollPosController(itemCount: 0);
  final PageController pageController = PageController();
  int selected = 0;

  DesktopTabState() {
    scrollController.itemCount = tabs.length;
  }
}

class DesktopTabController {
  final state = DesktopTabState().obs;
  final DesktopTabType tabType;

  /// index, key
  Function(int, String)? onRemove;
  Function(int)? onSelected;

  DesktopTabController({required this.tabType});

  void add(TabInfo tab, {bool authorized = false}) {
    if (!isDesktop) return;
    final index = state.value.tabs.indexWhere((e) => e.key == tab.key);
    int toIndex;
    if (index >= 0) {
      toIndex = index;
    } else {
      state.update((val) {
        val!.tabs.add(tab);
      });
      state.value.scrollController.itemCount = state.value.tabs.length;
      toIndex = state.value.tabs.length - 1;
      assert(toIndex >= 0);
    }
    if (tabType == DesktopTabType.cm) {
      Future.delayed(Duration.zero, () async {
        window_on_top(null);
      });
      if (authorized) {
        Future.delayed(const Duration(seconds: 3), () {
          windowManager.minimize();
        });
      }
    }
    try {
      jumpTo(toIndex);
    } catch (e) {
      // call before binding controller will throw
      debugPrint("Failed to jumpTo: $e");
    }
  }

  void remove(int index) {
    if (!isDesktop) return;
    final len = state.value.tabs.length;
    if (index < 0 || index > len - 1) return;
    final key = state.value.tabs[index].key;
    final currentSelected = state.value.selected;
    int toIndex = 0;
    if (index == len - 1) {
      toIndex = max(0, currentSelected - 1);
    } else if (index < len - 1 && index < currentSelected) {
      toIndex = max(0, currentSelected - 1);
    }
    state.value.tabs.removeAt(index);
    state.value.scrollController.itemCount = state.value.tabs.length;
    jumpTo(toIndex);
    onRemove?.call(index, key);
  }

  void jumpTo(int index) {
    if (!isDesktop || index < 0) return;
    state.update((val) {
      val!.selected = index;
      Future.delayed(Duration.zero, (() {
        if (val.pageController.hasClients) {
          val.pageController.jumpToPage(index);
        }
        if (val.scrollController.hasClients &&
            val.scrollController.canScroll &&
            val.scrollController.itemCount > index) {
          val.scrollController.scrollToItem(index, center: true, animate: true);
        }
      }));
    });
    if (state.value.tabs.length > index) {
      onSelected?.call(index);
    }
  }

  void jumpBy(String key) {
    if (!isDesktop) return;
    final index = state.value.tabs.indexWhere((tab) => tab.key == key);
    jumpTo(index);
  }

  void closeBy(String? key) {
    if (!isDesktop) return;
    assert(onRemove != null);
    if (key == null) {
      if (state.value.selected < state.value.tabs.length) {
        remove(state.value.selected);
      }
    } else {
      final index = state.value.tabs.indexWhere((tab) => tab.key == key);
      remove(index);
    }
  }

  void clear() {
    state.value.tabs.clear();
    state.refresh();
  }
}

class TabThemeConf {
  double iconSize;
  TabThemeConf({required this.iconSize});
}

typedef TabBuilder = Widget Function(
    String key, Widget icon, Widget label, TabThemeConf themeConf);
typedef LabelGetter = Rx<String> Function(String key);

class DesktopTab extends StatelessWidget {
  final Function(String)? onTabClose;
  final bool showTabBar;
  final bool showLogo;
  final bool showTitle;
  final bool showMinimize;
  final bool showMaximize;
  final bool showClose;
  final Widget Function(Widget pageView)? pageViewBuilder;
  final Widget? tail;
  final Future<bool> Function()? onWindowCloseButton;
  final TabBuilder? tabBuilder;
  final LabelGetter? labelGetter;

  final DesktopTabController controller;
  Rx<DesktopTabState> get state => controller.state;
  late final DesktopTabType tabType;
  late final bool isMainWindow;

  DesktopTab({
    Key? key,
    required this.controller,
    this.onTabClose,
    this.showTabBar = true,
    this.showLogo = true,
    this.showTitle = true,
    this.showMinimize = true,
    this.showMaximize = true,
    this.showClose = true,
    this.pageViewBuilder,
    this.tail,
    this.onWindowCloseButton,
    this.tabBuilder,
    this.labelGetter,
  }) : super(key: key) {
    tabType = controller.tabType;
    isMainWindow =
        tabType == DesktopTabType.main || tabType == DesktopTabType.cm;
  }

  @override
  Widget build(BuildContext context) {
    return Column(children: [
      Offstage(
          offstage: !showTabBar,
          child: SizedBox(
            height: _kTabBarHeight,
            child: Column(
              children: [
                SizedBox(
                  height: _kTabBarHeight - 1,
                  child: _buildBar(),
                ),
                const Divider(
                  height: 1,
                  thickness: 1,
                ),
              ],
            ),
          )),
      Expanded(
          child: pageViewBuilder != null
              ? pageViewBuilder!(_buildPageView())
              : _buildPageView())
    ]);
  }

  Widget _buildBlock({required Widget child}) {
    if (tabType != DesktopTabType.main) {
      return child;
    }
    var block = false.obs;
    return Obx(() => MouseRegion(
          onEnter: (_) async {
            if (!option2bool(
                'allow-remote-config-modification',
                await bind.mainGetOption(
                    key: 'allow-remote-config-modification'))) {
              var time0 = DateTime.now().millisecondsSinceEpoch;
              await bind.mainCheckMouseTime();
              Timer(const Duration(milliseconds: 120), () async {
                var d = time0 - await bind.mainGetMouseTime();
                if (d < 120) {
                  block.value = true;
                }
              });
            }
          },
          onExit: (_) => block.value = false,
          child: Stack(
            children: [
              child,
              Offstage(
                  offstage: !block.value,
                  child: Container(
                    color: Colors.black.withOpacity(0.5),
                  )),
            ],
          ),
        ));
  }

  Widget _buildPageView() {
    return _buildBlock(
        child: Obx(() => PageView(
            controller: state.value.pageController,
            children: state.value.tabs
                .map((tab) => tab.page)
                .toList(growable: false))));
  }

  Widget _buildBar() {
    return Row(
      children: [
        Expanded(
          child: Row(
            children: [
              Offstage(
                  offstage: !Platform.isMacOS,
                  child: const SizedBox(
                    width: 78,
                  )),
              Row(children: [
                Offstage(
                    offstage: !showLogo,
                    child: SvgPicture.asset(
                      'assets/logo.svg',
                      width: 16,
                      height: 16,
                    )),
                Offstage(
                    offstage: !showTitle,
                    child: const Text(
                      "RustDesk",
                      style: TextStyle(fontSize: 13),
                    ).marginOnly(left: 2))
              ]).marginOnly(
                left: 5,
                right: 10,
              ),
              Expanded(
                child: GestureDetector(
                    onPanStart: (_) {
                      if (isMainWindow) {
                        windowManager.startDragging();
                      } else {
                        WindowController.fromWindowId(windowId!)
                            .startDragging();
                      }
                    },
                    child: _ListView(
                      controller: controller,
                      onTabClose: onTabClose,
                      tabBuilder: tabBuilder,
                      labelGetter: labelGetter,
                    )),
              ),
            ],
          ),
        ),
        Offstage(offstage: tail == null, child: tail),
        WindowActionPanel(
          mainTab: isMainWindow,
          tabType: tabType,
          state: state,
          showMinimize: showMinimize,
          showMaximize: showMaximize,
          showClose: showClose,
          onClose: onWindowCloseButton,
        )
      ],
    );
  }
}

class WindowActionPanel extends StatelessWidget {
  final bool mainTab;
  final DesktopTabType tabType;
  final Rx<DesktopTabState> state;

  final bool showMinimize;
  final bool showMaximize;
  final bool showClose;
  final Future<bool> Function()? onClose;

  const WindowActionPanel(
      {Key? key,
      required this.mainTab,
      required this.tabType,
      required this.state,
      this.showMinimize = true,
      this.showMaximize = true,
      this.showClose = true,
      this.onClose})
      : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Offstage(
            offstage: !showMinimize,
            child: ActionIcon(
              message: 'Minimize',
              icon: IconFont.min,
              onTap: () {
                if (mainTab) {
                  windowManager.minimize();
                } else {
                  WindowController.fromWindowId(windowId!).minimize();
                }
              },
              isClose: false,
            )),
        // TODO: drag makes window restore
        Offstage(
            offstage: !showMaximize,
            child: FutureBuilder(builder: (context, snapshot) {
              RxBool isMaximized = false.obs;
              if (mainTab) {
                windowManager.isMaximized().then((maximized) {
                  isMaximized.value = maximized;
                });
              } else {
                final wc = WindowController.fromWindowId(windowId!);
                wc.isMaximized().then((maximized) {
                  isMaximized.value = maximized;
                });
              }
              return Obx(
                () => ActionIcon(
                  message: isMaximized.value ? "Restore" : "Maximize",
                  icon: isMaximized.value ? IconFont.restore : IconFont.max,
                  onTap: () {
                    if (mainTab) {
                      if (isMaximized.value) {
                        windowManager.unmaximize();
                      } else {
                        windowManager.maximize();
                      }
                    } else {
                      // TODO: subwindow is maximized but first query result is not maximized.
                      final wc = WindowController.fromWindowId(windowId!);
                      if (isMaximized.value) {
                        wc.unmaximize();
                      } else {
                        wc.maximize();
                      }
                    }
                    isMaximized.value = !isMaximized.value;
                  },
                  isClose: false,
                ),
              );
            })),
        Offstage(
            offstage: !showClose,
            child: ActionIcon(
              message: 'Close',
              icon: IconFont.close,
              onTap: () async {
                final res = await onClose?.call() ?? true;
                if (res) {
                  if (mainTab) {
                    windowManager.close();
                  } else {
                    // only hide for multi window, not close
                    Future.delayed(Duration.zero, () {
                      WindowController.fromWindowId(windowId!).hide();
                    });
                  }
                }
              },
              isClose: true,
            )),
      ],
    );
  }
}

Future<bool> closeConfirmDialog() async {
  final res = await gFFI.dialogManager.show<bool>((setState, close) {
    submit() => close(true);
    return CustomAlertDialog(
      title: Row(children: [
        const Icon(Icons.warning_amber_sharp,
            color: Colors.redAccent, size: 28),
        const SizedBox(width: 10),
        Text(translate("Warning")),
      ]),
      content: Text(translate("Disconnect all devices?")),
      actions: [
        TextButton(onPressed: close, child: Text(translate("Cancel"))),
        ElevatedButton(onPressed: submit, child: Text(translate("OK"))),
      ],
      onSubmit: submit,
      onCancel: close,
    );
  });
  return res == true;
}

// ignore: must_be_immutable
class _ListView extends StatelessWidget {
  final DesktopTabController controller;
  final Function(String key)? onTabClose;

  final TabBuilder? tabBuilder;
  final LabelGetter? labelGetter;

  Rx<DesktopTabState> get state => controller.state;

  const _ListView(
      {required this.controller,
      required this.onTabClose,
      this.tabBuilder,
      this.labelGetter});

  /// Check whether to show ListView
  ///
  /// Conditions:
  /// - hide single item when only has one item (home) on [DesktopTabPage].
  bool isHideSingleItem() {
    return state.value.tabs.length == 1 &&
        controller.tabType == DesktopTabType.main;
  }

  @override
  Widget build(BuildContext context) {
    return Obx(() => ListView(
        controller: state.value.scrollController,
        scrollDirection: Axis.horizontal,
        shrinkWrap: true,
        physics: const BouncingScrollPhysics(),
        children: isHideSingleItem()
            ? List.empty()
            : state.value.tabs.asMap().entries.map((e) {
                final index = e.key;
                final tab = e.value;
                return _Tab(
                  index: index,
                  label: labelGetter == null
                      ? Rx<String>(tab.label)
                      : labelGetter!(tab.label),
                  selectedIcon: tab.selectedIcon,
                  unselectedIcon: tab.unselectedIcon,
                  closable: tab.closable,
                  selected: state.value.selected,
                  onClose: () {
                    if (tab.onTabCloseButton != null) {
                      tab.onTabCloseButton!();
                    } else {
                      controller.remove(index);
                    }
                  },
                  onSelected: () => controller.jumpTo(index),
                  tabBuilder: tabBuilder == null
                      ? null
                      : (Widget icon, Widget labelWidget,
                          TabThemeConf themeConf) {
                          return tabBuilder!(
                            tab.label,
                            icon,
                            labelWidget,
                            themeConf,
                          );
                        },
                );
              }).toList()));
  }
}

class _Tab extends StatefulWidget {
  final int index;
  final Rx<String> label;
  final IconData? selectedIcon;
  final IconData? unselectedIcon;
  final bool closable;
  final int selected;
  final Function() onClose;
  final Function() onSelected;
  final Widget Function(Widget icon, Widget label, TabThemeConf themeConf)?
      tabBuilder;

  const _Tab({
    Key? key,
    required this.index,
    required this.label,
    this.selectedIcon,
    this.unselectedIcon,
    this.tabBuilder,
    required this.closable,
    required this.selected,
    required this.onClose,
    required this.onSelected,
  }) : super(key: key);

  @override
  State<_Tab> createState() => _TabState();
}

class _TabState extends State<_Tab> with RestorationMixin {
  final RestorableBool restoreHover = RestorableBool(false);

  Widget _buildTabContent() {
    bool showIcon =
        widget.selectedIcon != null && widget.unselectedIcon != null;
    bool isSelected = widget.index == widget.selected;

    final icon = Offstage(
        offstage: !showIcon,
        child: Icon(
          isSelected ? widget.selectedIcon : widget.unselectedIcon,
          size: _kIconSize,
          color: isSelected
              ? MyTheme.tabbar(context).selectedTabIconColor
              : MyTheme.tabbar(context).unSelectedTabIconColor,
        ).paddingOnly(right: 5));
    final labelWidget = Obx(() {
      return Text(
        translate(widget.label.value),
        textAlign: TextAlign.center,
        style: TextStyle(
            color: isSelected
                ? MyTheme.tabbar(context).selectedTextColor
                : MyTheme.tabbar(context).unSelectedTextColor),
      );
    });

    if (widget.tabBuilder == null) {
      return Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          icon,
          labelWidget,
        ],
      );
    } else {
      return widget.tabBuilder!(
          icon, labelWidget, TabThemeConf(iconSize: _kIconSize));
    }
  }

  @override
  Widget build(BuildContext context) {
    bool isSelected = widget.index == widget.selected;
    bool showDivider =
        widget.index != widget.selected - 1 && widget.index != widget.selected;
    RxBool hover = restoreHover.value.obs;
    return Ink(
      child: InkWell(
        onHover: (value) {
          hover.value = value;
          restoreHover.value = value;
        },
        onTap: () => widget.onSelected(),
        child: Row(
          children: [
            SizedBox(
                height: _kTabBarHeight,
                child: Row(
                    crossAxisAlignment: CrossAxisAlignment.center,
                    children: [
                      _buildTabContent(),
                      Obx((() => _CloseButton(
                            visiable: hover.value && widget.closable,
                            tabSelected: isSelected,
                            onClose: () => widget.onClose(),
                          )))
                    ])).paddingSymmetric(horizontal: 10),
            Offstage(
              offstage: !showDivider,
              child: VerticalDivider(
                width: 1,
                indent: _kDividerIndent,
                endIndent: _kDividerIndent,
                color: MyTheme.tabbar(context).dividerColor,
                thickness: 1,
              ),
            )
          ],
        ),
      ),
    );
  }

  @override
  String? get restorationId => "_Tab${widget.label.value}";

  @override
  void restoreState(RestorationBucket? oldBucket, bool initialRestore) {
    registerForRestoration(restoreHover, 'restoreHover');
  }
}

class _CloseButton extends StatelessWidget {
  final bool visiable;
  final bool tabSelected;
  final Function onClose;

  const _CloseButton({
    Key? key,
    required this.visiable,
    required this.tabSelected,
    required this.onClose,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return SizedBox(
        width: _kIconSize,
        child: Offstage(
          offstage: !visiable,
          child: InkWell(
            customBorder: const RoundedRectangleBorder(),
            onTap: () => onClose(),
            child: Icon(
              Icons.close,
              size: _kIconSize,
              color: tabSelected
                  ? MyTheme.tabbar(context).selectedIconColor
                  : MyTheme.tabbar(context).unSelectedIconColor,
            ),
          ),
        )).paddingOnly(left: 5);
  }
}

class ActionIcon extends StatelessWidget {
  final String message;
  final IconData icon;
  final Function() onTap;
  final bool isClose;
  const ActionIcon({
    Key? key,
    required this.message,
    required this.icon,
    required this.onTap,
    required this.isClose,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    RxBool hover = false.obs;
    return Obx(() => Tooltip(
          message: translate(message),
          waitDuration: const Duration(seconds: 1),
          child: InkWell(
            hoverColor: isClose
                ? const Color.fromARGB(255, 196, 43, 28)
                : MyTheme.tabbar(context).hoverColor,
            onHover: (value) => hover.value = value,
            onTap: onTap,
            child: SizedBox(
              height: _kTabBarHeight - 1,
              width: _kTabBarHeight - 1,
              child: Icon(
                icon,
                color: hover.value && isClose
                    ? Colors.white
                    : MyTheme.tabbar(context).unSelectedIconColor,
                size: _kActionIconSize,
              ),
            ),
          ),
        ));
  }
}

class AddButton extends StatelessWidget {
  const AddButton({
    Key? key,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return ActionIcon(
        message: 'New Connection',
        icon: IconFont.add,
        onTap: () =>
            rustDeskWinManager.call(WindowType.Main, "main_window_on_top", ""),
        isClose: false);
  }
}

class TabbarTheme extends ThemeExtension<TabbarTheme> {
  final Color? selectedTabIconColor;
  final Color? unSelectedTabIconColor;
  final Color? selectedTextColor;
  final Color? unSelectedTextColor;
  final Color? selectedIconColor;
  final Color? unSelectedIconColor;
  final Color? dividerColor;
  final Color? hoverColor;

  const TabbarTheme(
      {required this.selectedTabIconColor,
      required this.unSelectedTabIconColor,
      required this.selectedTextColor,
      required this.unSelectedTextColor,
      required this.selectedIconColor,
      required this.unSelectedIconColor,
      required this.dividerColor,
      required this.hoverColor});

  static const light = TabbarTheme(
      selectedTabIconColor: MyTheme.accent,
      unSelectedTabIconColor: Color.fromARGB(255, 162, 203, 241),
      selectedTextColor: Color.fromARGB(255, 26, 26, 26),
      unSelectedTextColor: Color.fromARGB(255, 96, 96, 96),
      selectedIconColor: Color.fromARGB(255, 26, 26, 26),
      unSelectedIconColor: Color.fromARGB(255, 96, 96, 96),
      dividerColor: Color.fromARGB(255, 238, 238, 238),
      hoverColor: Color.fromARGB(51, 158, 158, 158));

  static const dark = TabbarTheme(
      selectedTabIconColor: MyTheme.accent,
      unSelectedTabIconColor: Color.fromARGB(255, 30, 65, 98),
      selectedTextColor: Color.fromARGB(255, 255, 255, 255),
      unSelectedTextColor: Color.fromARGB(255, 207, 207, 207),
      selectedIconColor: Color.fromARGB(255, 215, 215, 215),
      unSelectedIconColor: Color.fromARGB(255, 255, 255, 255),
      dividerColor: Color.fromARGB(255, 64, 64, 64),
      hoverColor: Colors.black26);

  @override
  ThemeExtension<TabbarTheme> copyWith({
    Color? selectedTabIconColor,
    Color? unSelectedTabIconColor,
    Color? selectedTextColor,
    Color? unSelectedTextColor,
    Color? selectedIconColor,
    Color? unSelectedIconColor,
    Color? dividerColor,
    Color? hoverColor,
  }) {
    return TabbarTheme(
      selectedTabIconColor: selectedTabIconColor ?? this.selectedTabIconColor,
      unSelectedTabIconColor:
          unSelectedTabIconColor ?? this.unSelectedTabIconColor,
      selectedTextColor: selectedTextColor ?? this.selectedTextColor,
      unSelectedTextColor: unSelectedTextColor ?? this.unSelectedTextColor,
      selectedIconColor: selectedIconColor ?? this.selectedIconColor,
      unSelectedIconColor: unSelectedIconColor ?? this.unSelectedIconColor,
      dividerColor: dividerColor ?? this.dividerColor,
      hoverColor: hoverColor ?? this.hoverColor,
    );
  }

  @override
  ThemeExtension<TabbarTheme> lerp(
      ThemeExtension<TabbarTheme>? other, double t) {
    if (other is! TabbarTheme) {
      return this;
    }
    return TabbarTheme(
      selectedTabIconColor:
          Color.lerp(selectedTabIconColor, other.selectedTabIconColor, t),
      unSelectedTabIconColor:
          Color.lerp(unSelectedTabIconColor, other.unSelectedTabIconColor, t),
      selectedTextColor:
          Color.lerp(selectedTextColor, other.selectedTextColor, t),
      unSelectedTextColor:
          Color.lerp(unSelectedTextColor, other.unSelectedTextColor, t),
      selectedIconColor:
          Color.lerp(selectedIconColor, other.selectedIconColor, t),
      unSelectedIconColor:
          Color.lerp(unSelectedIconColor, other.unSelectedIconColor, t),
      dividerColor: Color.lerp(dividerColor, other.dividerColor, t),
      hoverColor: Color.lerp(hoverColor, other.hoverColor, t),
    );
  }

  static color(BuildContext context) {
    return Theme.of(context).extension<ColorThemeExtension>()!;
  }
}

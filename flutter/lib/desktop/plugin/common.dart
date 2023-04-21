import 'dart:convert';

typedef PluginId = String;

// ui location
const String kLocationHostMainDisplayOthers =
    'host|main|settings|display|others';
const String kLocationClientRemoteToolbarDisplay =
    'client|remote|toolbar|display';

class MsgFromUi {
  String remotePeerId;
  String localPeerId;
  String id;
  String name;
  String location;
  String key;
  String value;
  String action;

  MsgFromUi({
    required this.remotePeerId,
    required this.localPeerId,
    required this.id,
    required this.name,
    required this.location,
    required this.key,
    required this.value,
    required this.action,
  });

  Map<String, dynamic> toJson() {
    return <String, dynamic>{
      'remote_peer_id': remotePeerId,
      'local_peer_id': localPeerId,
      'id': id,
      'name': name,
      'location': location,
      'key': key,
      'value': value,
      'action': action,
    };
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

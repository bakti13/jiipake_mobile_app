import 'dart:convert';
import 'dart:io';
import 'package:webview_flutter/webview_flutter.dart';

import 'package:flutter/material.dart';
import 'package:jiipake_app/exchange.dart';

void main() async {
  // modify with your true address/port
  String ip = (Platform.isAndroid) ? '10.0.2.2' : 'localhost';
  Socket sock = await Socket.connect(ip, Exchange.PORT); // ignore: close_sinks
  runApp(MyApp(sock));
}

class MyApp extends StatelessWidget {
  // ignore: must_be_immutable
  Socket socket;

  MyApp(Socket s) {
    this.socket = s;
  }

  @override
  Widget build(BuildContext context) {
    final title = 'Jiipake Protocol Demo';
    return MaterialApp(
      title: title,
      home: MyHomePage(
        title: title,
        channel: socket,
        exchange: Exchange(),
      ),
    );
  }
}

class MyHomePage extends StatefulWidget {
  final String title;
  final Socket channel;
  final Exchange exchange;

  MyHomePage(
      {Key key,
      @required this.title,
      @required this.channel,
      @required this.exchange})
      : super(key: key);

  @override
  _MyHomePageState createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  BigInt A, x4, gx2, gx3, hashKeys;
  String result = "", key;
  TextEditingController _controller = TextEditingController();

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(widget.title),
      ),
      body: Padding(
        padding: const EdgeInsets.all(20.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            Form(
              child: TextFormField(
                controller: _controller,
                decoration: InputDecoration(labelText: 'Send a secret key'),
              ),
            ),
            StreamBuilder(
                stream: widget.channel,
                builder: (context, snapshot) {
                  String message = snapshot.hasData
                      ? String.fromCharCodes(snapshot.data)
                      : '';
                  bool valid = false;
                  if (message.startsWith('{')) {
                    // valid = false;
                    Map<String, dynamic> fromJson = jsonDecode(message);
                    //check if return gx2
                    if (fromJson.containsKey("gx1")) {
                      // valid = false;
                      // print(' message 1: $message');
                      // print('receiving from server messege1');
                      BigInt gx1 = BigInt.parse(fromJson['gx1'].toString());
                      gx2 = BigInt.parse(fromJson['gx2'].toString());
                      List<BigInt> sigX1 = List<String>.from(fromJson['ZKP1'])
                          .map((data) => BigInt.parse(data))
                          .toList();
                      List<BigInt> sigX2 = List<String>.from(fromJson['ZKP2'])
                          .map((data) => BigInt.parse(data))
                          .toList();
                      result += "Receiving g^{x1}, g^{x2} from Server\n";

                      if (widget.exchange.cekZKP(gx1, gx2, sigX1, sigX2)) {
                        // valid = false;
                        // print("**********ZKP VALID*******");
                        Map<String, dynamic> roundTwo = _roundTwo(gx1);
                        var date = DateTime.fromMillisecondsSinceEpoch(
                            (DateTime.now().millisecondsSinceEpoch));
                        result += "verifies Server's ZKPs : OK\nTimestamp: ${date}\n";

                        widget.channel.writeln(JsonEncoder().convert(roundTwo));
                      }
                    } else if (fromJson.containsKey("A")) {
                      // valid = false;
                      // print(' message 2: $message');
                      A = BigInt.parse(fromJson['A'].toString());
                      BigInt gA = BigInt.parse(fromJson['gA'].toString());
                      List<BigInt> sigX2s =
                          List<String>.from(fromJson['KP{x2*s}'])
                              .map((data) => BigInt.parse(data))
                              .toList();

                      result += "Receiving A and KP{x2*s} from Server\n";

                      if (widget.exchange.chekZKPs(gA, A, sigX2s)) {
                        // valid = false;
                        hashKeys = widget.exchange.getSessionKeys(
                            gx2,
                            x4,
                            A,
                            BigInt.parse(
                                (_controller.text.codeUnits).join("")));
                        // sleep(const Duration(milliseconds: 200));
                        var date = DateTime.fromMillisecondsSinceEpoch(
                            (DateTime.now().millisecondsSinceEpoch));
                        String keyStr = '${hashKeys.toString()};$date';

                        result += "verifies Server's KP{x2*s} : OK\nTimestamp: ${date}\n";
                        result += "**********************\n";
                        result += "Generating key:\n";
                        result += '$keyStr\n';
                        result += "**********************\n";
                        widget.channel.writeln(keyStr);
                      } else {
                        // print("********** ZKPs NOT VALID*******");
                      }
                    }
                  } else if (message.startsWith(new RegExp(r'[0-9]'))) {
                    // check secret key
                    valid = _validateKey(message, hashKeys) == "VALID"
                        ? true
                        : false;
                    result += 'Status Key: ${_validateKey(message, hashKeys)}';
                  } else if (message.isNotEmpty) {
                    // valid = false;
                    result += 'Error!!';
                  }
                  if (valid) {
                    return Expanded(
                      child: Container(
                        constraints:
                            BoxConstraints(minWidth: 100, maxWidth: 400),
                        child: WebView(
                          initialUrl: 'https://www.google.com/',
                          javascriptMode: JavascriptMode.unrestricted,
                        ),
                      ),
                    );
                  } else {
                    return Expanded(
                      child: Text(
                        result,
                        overflow: TextOverflow.clip,
                      ),
                    );
                  }
                })
          ],
        ),
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: _sendMessage,
        tooltip: 'Send secret key',
        child: Icon(Icons.send),
      ), // This trailing comma makes auto-formatting nicer for build methods.
    );
  }

  void _sendMessage() {
    if (_controller.text.isNotEmpty) {
      result = "";
      key = _controller.text;
      widget.channel.writeln(JsonEncoder().convert(_roundOne()));
    }
  }

  _roundOne() {
    x4 = BigInt.parse(Exchange.secureRandom(), radix: 10);
    Map<String, dynamic> roundOne = widget.exchange.roundOne(
        BigInt.parse(Exchange.secureRandom(), radix: 10),
        x4,
        Exchange.CLIENTID);
    gx3 = BigInt.parse(roundOne['gx3']);
    return roundOne;
  }

  _roundTwo(BigInt gx1) {
    BigInt keys = BigInt.tryParse((key.codeUnits).join(""), radix: 10);
    return widget.exchange.roundTwo(gx3, gx1, gx2, x4, keys);
  }

  @override
  void dispose() {
    widget.channel.close();
    super.dispose();
  }

  _validateKey(String message, BigInt hashKeys) {
    List<String> keys = message.split(';');
    return (hashKeys.toString()) == keys[0] ? 'VALID' : 'NOT VALID';
  }
}

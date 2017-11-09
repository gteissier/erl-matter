# Verifying Erlang distribution usage in top eight trendy Erlang servers

All images have been pulled from hub.docker.com, and official images when possible. In order to scan ports, an [nmap image](https://hub.docker.com/r/k0st/nmap/) has been pulled. The [dedicated NSE plugin](erldp-info.nse) has been used to actively detect Erlang distribution port(s).

## rabbitmq/rabbitmq-server: Open source multi-protocol messaging broker

Pull docker image

```
$ docker pull rabbitmq
```

Start one instance:

```
$ docker run -ti --rm --name rabbitmq rabbitmq
```

Scan it:

```
$ docker run --rm -ti --link rabbitmq -v "$PWD":/erl-matter:ro k0st/nmap -sT -p- --script=/erl-matter/erldp-info.nse 172.17.0.2

Starting Nmap 6.47 ( http://nmap.org ) at 2017-11-09 20:39 UTC
Nmap scan report for rabbitmq (172.17.0.2)
Host is up (0.00066s latency).
Not shown: 65532 closed ports
PORT      STATE SERVICE
4369/tcp  open  epmd
5672/tcp  open  amqp
25672/tcp open  erldp
| erldp-info:
|   version: 5
|   node: rabbit@619f10575c36
|_  flags: 77ffc
MAC Address: 02:42:AC:11:00:02 (Unknown)
```

## emqtt/emqttd: EMQ - Erlang MQTT Broker

Pull docker image:

```
$ docker pull emqttd/emqttd
```

Start one instance (yes, this image does start emqttd when started):

```
$ docker run -ti --rm --name emqttd emqttd/emqttd
[root@8bb7f21511f8 /]# emqttd_start
```

Scan it:

```
$ docker run --rm -ti --link emqttd -v "$PWD":/erl-matter:ro k0st/nmap -sT -p- --script=/erl-matter/erldp-info.nse 172.17.0.2

Starting Nmap 6.47 ( http://nmap.org ) at 2017-11-09 20:37 UTC
Nmap scan report for emqttd (172.17.0.2)
Host is up (0.00071s latency).
Not shown: 65529 closed ports
PORT      STATE SERVICE
1883/tcp  open  unknown
4369/tcp  open  epmd
8083/tcp  open  us-srv
8883/tcp  open  unknown
18083/tcp open  unknown
33005/tcp open  erldp
| erldp-info:
|   version: 5
|   node: emqttd@127.0.0.1
|_  flags: 37ffc
MAC Address: 02:42:AC:11:00:02 (Unknown)
```

## ninesnines/cowboy: Small, fast, modern HTTP server for Erlang/OTP

Pull docker image

```
$ docker pull ontouchstart/cowboy
```

Start one instance:

```
root@c8d0bdc6bd7d:/# cd cowboy/examples/hello_world/
root@c8d0bdc6bd7d:/cowboy/examples/hello_world# make
...
root@c8d0bdc6bd7d:/cowboy/examples/hello_world# cd _rel/hello_world_example/bin/
root@c8d0bdc6bd7d:/cowboy/examples/hello_world/_rel/hello_world_example/bin# ./hello_world_example start
```

Scan it:

```
$ docker run --rm -ti --link cowboy -v "$PWD":/erl-matter:ro k0st/nmap -sT -p- --script=/erl-matter/erldp-info.nse 172.17.0.2

Starting Nmap 6.47 ( http://nmap.org ) at 2017-11-09 20:47 UTC
Nmap scan report for cowboy (172.17.0.2)
Host is up (0.00070s latency).
Not shown: 65532 closed ports
PORT      STATE SERVICE
4369/tcp  open  epmd
8080/tcp  open  http-proxy
43421/tcp open  erldp
| erldp-info:
|   version: 5
|   node: hello_world_example@127.0.0.1
|_  flags: 37ffc
MAC Address: 02:42:AC:11:00:02 (Unknown)
```

## apache/couchdb: Apache CouchDB

CouchDB is well protected, it does not expose Erlang distribution by default.

Pull docker image:

```
$ docker pull couchdb
```

Start one instance:

```
$ docker run -ti --rm --name couchdb couchdb
```

Scan it:

```
$ docker run --rm -ti --link couchdb -v "$PWD":/erl-matter:ro k0st/nmap -sT -p- --script=/erl-matter/erldp-info.nse 172.17.0.2

Starting Nmap 6.47 ( http://nmap.org ) at 2017-11-09 20:53 UTC
Nmap scan report for couchdb (172.17.0.2)
Host is up (0.00069s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE
5984/tcp open  unknown
5986/tcp open  wsmans
MAC Address: 02:42:AC:11:00:02 (Unknown)
```

## processone/ejabberd: Robust, ubiquitous and massively scalable Jabber / XMPP Instant Messaging platform

Pull docker image, no official docker image seems to be available:

```
$ docker pull rroemhild/ejabberd
```

Start one instance:

```
$ docker run -ti --rm --name ejabberd rroemhild/ejabberd
```

Scan it:

```
$ docker run --rm -ti --link ejabberd -v "$PWD":/erl-matter:ro k0st/nmap -sT -p- --script=/erl-matter/erldp-info.nse 172.17.0.2

Starting Nmap 6.47 ( http://nmap.org ) at 2017-11-09 21:02 UTC
Nmap scan report for ejabberd (172.17.0.2)
Host is up (0.00079s latency).
Not shown: 65528 closed ports
PORT      STATE SERVICE
4369/tcp  open  epmd
4560/tcp  open  unknown
5222/tcp  open  xmpp-client
5269/tcp  open  xmpp-server
5280/tcp  open  xmpp-bosh
5443/tcp  open  unknown
34925/tcp open  erldp
| erldp-info:
|   version: 5
|   node: ejabberd@localhost
|_  flags: 77ffc
MAC Address: 02:42:AC:11:00:02 (Unknown)
```


## erlio/vernemq: A distributed MQTT message broker based on Erlang/OTP

Pull docker image:

```
docker pull erlio/docker-vernemq
```

Start one instance:

```
$ docker run -ti --rm --name emqttd erlio/docker-vernemq
```

Scan it:

```
$ docker run --rm -ti --link emqttd -v "$PWD":/erl-matter:ro k0st/nmap -sT -p- --script=/erl-matter/erldp-info.nse 172.17.0.2

Starting Nmap 6.47 ( http://nmap.org ) at 2017-11-09 21:05 UTC
Nmap scan report for emqttd (172.17.0.2)
Host is up (0.00077s latency).
Not shown: 65529 closed ports
PORT      STATE SERVICE
1883/tcp  open  unknown
4369/tcp  open  epmd
8080/tcp  open  http-proxy
8888/tcp  open  sun-answerbook
9100/tcp  open  erldp
| erldp-info:
|   version: 5
|   node: VerneMQ@172.17.0.2
|_  flags: 77ffc
44053/tcp open  unknown
MAC Address: 02:42:AC:11:00:02 (Unknown)
```

## gotthardp/lorawan-server: Compact server for private LoRa networks

Pull docker image:

```
$ docker run -ti --rm --name lorawan gotthardp/lorawan-server
```

Start one instance:

```
$ docker run -ti --rm --name lorawan gotthardp/lorawan-server
```

Scan it:

```
$ docker run --rm -ti --link lorawan -v "$PWD":/erl-matter:ro k0st/nmap -sT -p- --script=/erl-matter/erldp-info.nse 172.17.0.2

Starting Nmap 6.47 ( http://nmap.org ) at 2017-11-09 21:09 UTC
Nmap scan report for lorawan (172.17.0.2)
Host is up (0.00075s latency).
Not shown: 65532 closed ports
PORT      STATE SERVICE
4369/tcp  open  epmd
8080/tcp  open  http-proxy
38151/tcp open  erldp
| erldp-info:
|   version: 5
|   node: lorawan@c76344854f8d
|_  flags: 77ffc
```


## esl/MongooseIM: MongooseIM is a mobile messaging platform with focus on performance and scalability

Pull docker image:

```
$ docker pull mongooseim/mongooseim
```

Start one instance:

```
$ docker run -ti --rm -h mongooseim-1 --name mongooseim mongooseim/mongooseim
```

Scan it:

```
$ docker run --rm -ti --link mongooseim -v "$PWD":/erl-matter:ro k0st/nmap -sT -p- --script=/erl-matter/erldp-info.nse 172.17.0.2

Starting Nmap 6.47 ( http://nmap.org ) at 2017-11-09 21:13 UTC
Nmap scan report for mongooseim (172.17.0.2)
Host is up (0.00070s latency).
Not shown: 65528 closed ports
PORT      STATE SERVICE
4369/tcp  open  epmd
5222/tcp  open  xmpp-client
5269/tcp  open  xmpp-server
5280/tcp  open  xmpp-bosh
5285/tcp  open  unknown
8089/tcp  open  unknown
38673/tcp open  erldp
| erldp-info:
|   version: 5
|   node: mongooseim@mongooseim-1
|_  flags: 77ffc
MAC Address: 02:42:AC:11:00:02 (Unknown)
```

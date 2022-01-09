---
title: REvil Ransomware
categories:
  - Reverse Engineering
description: Malware Analysis Report - REvil Ransomware
---

# REvil Ransomware 

## Contents

- [REvil Ransomware](#revil-ransomware)
  - [Contents](#contents)
  - [Overview](#overview)
  - [IOCS](#iocs)
  - [Ransom Note](#ransom-note)
- [Static Code Analysis](#static-code-analysis)
  - [Anti-Analysis: Dynamic API Resolving](#anti-analysis-dynamic-api-resolving)
  - [Anti-Analysis: String Encryption](#anti-analysis-string-encryption)
  - [Configuration](#configuration)
  - [Command-line Arguments](#command-line-arguments)
  - [Generate Victim Information](#generate-victim-information)
    - [I. Victim Secret Key](#i-victim-secret-key)
    - [II. Victim ID](#ii-victim-id)
    - [III. Encrypted File Extension](#iii-encrypted-file-extension)
    - [IV. Full Victim Information Buffer](#iv-full-victim-information-buffer)
  - [Building Ransom Note](#building-ransom-note)
  - [Building Ransom Wallpaper Image](#building-ransom-wallpaper-image)
  - [Language Check](#language-check)
  - [Safemood Reboot](#safemood-reboot)
  - [Run-Once Mutex](#run-once-mutex)
  - [Priviledge Escalation](#priviledge-escalation)
  - [Pre-Encryption Setup](#pre-encryption-setup)
  - [Persistence](#persistence)
  - [Terminating Services and Processes through WMI](#terminating-services-and-processes-through-wmi)
  - [Terminating Services through Service Control Manager](#terminating-services-through-service-control-manager)
  - [Terminating Processes](#terminating-processes)
  - [Deleting Shadow Copies](#deleting-shadow-copies)
  - [File Encryption](#file-encryption)
    - [Multithreading setup](#multithreading-setup)
    - [Main Thread Traversal](#main-thread-traversal)
      - [I. Checking Directory Name](#i-checking-directory-name)
      - [II. Dropping Ransom Note](#ii-dropping-ransom-note)
      - [III. Traversal](#iii-traversal)
      - [IV. Pre-Encryption File Setup](#iv-pre-encryption-file-setup)
    - [Children Thread Encryption](#children-thread-encryption)
      - [I. State 1: Reading File](#i-state-1-reading-file)
      - [II. State 2. Encrypt and Write File](#ii-state-2-encrypt-and-write-file)
      - [III. State 3. Write File Footer](#iii-state-3-write-file-footer)
      - [IV. State 4. Move File](#iv-state-4-move-file)
    - [Network Shares Traversal](#network-shares-traversal)
    - [Drive Shares Traversal](#drive-shares-traversal)
    - [Network Drives and Resources Traversal](#network-drives-and-resources-traversal)
  - [Network Communication](#network-communication)
  - [Self-Deletion](#self-deletion)
  - [File Decryption](#file-decryption)
    - [I. Operator Key](#i-operator-key)
    - [II. Campaign Key](#ii-campaign-key)
    - [III. Decrypting the Victim Information Buffer](#iii-decrypting-the-victim-information-buffer)
  - [Personal Opinion](#personal-opinion)
  - [References](#references)

## Overview

This is my analysis for the **REvil Ransomware** payload found in the **Kaseya** incident. 


The report is my personal work, and it is not affiliated in any way to **FireEye/Mandiant's** engagement in said incident. 


This ransomware uses a hybrid-cryptography scheme of **Curve25519 ECDH** and **Salsa20** to encrypt files and protect its keys. 


It has an impressive multithreading approach to traverse and encrypt files as well as an ellaborate cryptography setup with multiple ways to decrypt files.


This new sample also has a new field in the configuration to control how many times the ransom notes are dropped on the system.

![alt text](/uploads/revil1.PNG)

![alt text](https://pbs.twimg.com/media/FIriGEIWYA0WYSv?format=jpg&name=large)

*Figure 1: REvil Ransomware leak site.*

## IOCS

This sample is a 32-bit **.exe** payload. 

**MD5**: 94d087166651c0020a9e6cc2fdacdc0c

**SHA256**: 9b11711efed24b3c6723521a7d7eb4a52e4914db7420e278aa36e727459d59dd

**Sample**: https://bazaar.abuse.ch/sample/9b11711efed24b3c6723521a7d7eb4a52e4914db7420e278aa36e727459d59dd/


![alt text](/uploads/revil2.PNG)

*Figure 2: VirusTotal information.*


## Ransom Note

The content of ransom note and the note's filename are extracted from REvil's configuration, and the **rdmcnt** field determines the total number of folders to drop the ransom note to.

The encrypted file extension, victim's ID, and key are dynamically generated and appended to the ransom note below.

![alt text](/uploads/revil3.PNG)

*Figure 3: REvil ransom note.*


# Static Code Analysis

## Anti-Analysis: Dynamic API Resolving 


Like all samples that came before, this **REvil** sample is obfuscated to hide its API calls from static analysis.

The original APIs are stored as an array of hashes in memory, and the malware dynamically resolves each by loading the appropriate DLL, hashing all of its exported APIs' name, and comparing the hashes to the unresolved API hash in memory.


Below is the hashing algorithm that the malware uses to hash API names.

![alt text](/uploads/revil4.PNG)

*Figure 4: API name hashing.*


Check out my IDAPython scripts [dll_exports.py](https://github.com/cdong1012/IDAPython-Malware-Scripts/blob/master/REvil/dll_exports.py) and [revil_api_resolve.py](https://github.com/cdong1012/IDAPython-Malware-Scripts/blob/master/REvil/revil_api_resolve.py) if you want to automate resolving these APIs. 
These scripts are inspired by this [OALabs's Youtube video](https://www.youtube.com/watch?v=R4xJou6JsIE).


## Anti-Analysis: String Encryption

Like all samples that came before, most strings in this **REvil** sample are encrypted and resolved during run-time.

The string decryption function takes in an offset and the length of the string to decrypt in a global encrypted string data buffer. After locating the encrypted string in the buffer, the malware decrypts it using **RC4**.


The best way to get around this is to use [flare-emu](https://github.com/fireeye/flare-emu) to emulate this function and extract all decrypted strings automatically.

Check out my IDAPython script for this [here](https://github.com/cdong1012/IDAPython-Malware-Scripts/blob/master/REvil/revil_string_decrypt.py). After running the script, each decrypted string is appended as a comment to its function call.

![alt text](/uploads/revil5.PNG)

*Figure 5: Automate string decryption.*


## Configuration

The configuration of REvil samples is encrypted and stored in memory.

The malware first computes the **CRC32** checksum of the encrypted config and compares it with a hard-coded checksum to ensure the configuration has not been tampered with.

Then, it decrypts the configuration using **RC4** using this key **"mXT1QFyEUbrxc4cbP84jbN5wrHeqmFXt"**.


![alt text](/uploads/revil6.PNG)

*Figure 6: REvil config decryption.*


Below is the sample's decrypted config in JSON form.


``` json
{
  "pk": "9/AgyLvWEviWbvuayR2k0Q140e9LZJ5hwrmto/zCyFM=",
  "pid": "$2a$12$prOX/4eKl8zrpGSC5lnHPecevs5NOckOUW5r3s4JJYDnZZSghvBkq",
  "sub": "8254",
  "dbg": false,
  "et": 0,
  "wipe": true,
  "wht": {
    "fld": [
      "program files",
      "appdata",
      "mozilla",
      "$windows.~ws",
      "application data",
      "$windows.~bt",
      "google",
      "$recycle.bin",
      "windows.old",
      "programdata",
      "system volume information",
      "program files (x86)",
      "boot",
      "tor browser",
      "windows",
      "intel",
      "perflogs",
      "msocache"
    ],
    "fls": [
      "ntldr",
      "thumbs.db",
      "bootsect.bak",
      "autorun.inf",
      "ntuser.dat.log",
      "boot.ini",
      "iconcache.db",
      "bootfont.bin",
      "ntuser.dat",
      "ntuser.ini",
      "desktop.ini"
    ],
    "ext": [
      "ps1",
      "ldf",
      "lock",
      "theme",
      "msi",
      "sys",
      "wpx",
      "cpl",
      "adv",
      "msc",
      "scr",
      "bat",
      "key",
      "ico",
      "dll",
      "hta",
      "deskthemepack",
      "nomedia",
      "msu",
      "rtp",
      "msp",
      "idx",
      "ani",
      "386",
      "diagcfg",
      "bin",
      "mod",
      "ics",
      "com",
      "hlp",
      "spl",
      "nls",
      "cab",
      "exe",
      "diagpkg",
      "icl",
      "ocx",
      "rom",
      "prf",
      "themepack",
      "msstyles",
      "lnk",
      "icns",
      "mpa",
      "drv",
      "cur",
      "diagcab",
      "cmd",
      "shs"
    ]
  },
  "wfld": [
    "backup"
  ],
  "prc": [
    "encsvc",
    "powerpnt",
    "ocssd",
    "steam",
    "isqlplussvc",
    "outlook",
    "sql",
    "ocomm",
    "agntsvc",
    "mspub",
    "onenote",
    "winword",
    "thebat",
    "excel",
    "mydesktopqos",
    "ocautoupds",
    "thunderbird",
    "synctime",
    "infopath",
    "mydesktopservice",
    "firefox",
    "oracle",
    "sqbcoreservice",
    "dbeng50",
    "tbirdconfig",
    "msaccess",
    "visio",
    "dbsnmp",
    "wordpad",
    "xfssvccon"
  ],
  "dmn": "boisehosting.net;fotoideaymedia.es;dubnew.com;stallbyggen.se;koken-voor-baby.nl;juneauopioidworkgroup.org;vancouver-print.ca;zewatchers.com;bouquet-de-roses.com;seevilla-dr-sturm.at;olejack.ru;i-trust.dk;wasmachtmeinfonds.at;appsformacpc.com;friendsandbrgrs.com;thenewrejuveme.com;xn--singlebrsen-vergleich-nec.com;sabel-bf.com;seminoc.com;ceres.org.au;cursoporcelanatoliquido.online;marietteaernoudts.nl;tastewilliamsburg.com;charlottepoudroux-photographie.fr;aselbermachen.com;klimt2012.info;accountancywijchen.nl;creamery201.com;rerekatu.com;makeurvoiceheard.com;vannesteconstruct.be;wellplast.se;andersongilmour.co.uk;bradynursery.com;aarvorg.com;facettenreich27.de;balticdermatology.lt;artige.com;highlinesouthasc.com;crowd-patch.co.uk;sofavietxinh.com;jorgobe.at;danskretursystem.dk;higadograsoweb.com;supportsumba.nl;ruralarcoiris.com;projetlyonturin.fr;kidbucketlist.com.au;harpershologram.wordpress.com;ohidesign.com;international-sound-awards.com;krlosdavid.com;durganews.com;leather-factory.co.jp;coding-machine.com;i-arslan.de;caribbeansunpoker.com;mir-na-iznanku.com;ki-lowroermond.nl;promesapuertorico.com;kissit.ca;dezatec.es;cite4me.org;grelot-home.com;musictreehouse.net;hkr-reise.de;id-vet.com;gasolspecialisten.se;vyhino-zhulebino-24.ru;karacaoglu.nl;bayoga.co.uk;solhaug.tk;jadwalbolanet.info;ncid.bc.ca;bricotienda.com;boldcitydowntown.com;homecomingstudio.com;sojamindbody.com;castillobalduz.es;asgestion.com;dushka.ua;hiddencitysecrets.com.au;danubecloud.com;roadwarrior.app;newstap.com.ng;no-plans.com;schoolofpassivewealth.com;senson.fi;denifl-consulting.at;lmtprovisions.com;talentwunder.com;acomprarseguidores.com;myzk.site;theapifactory.com;midmohandyman.com;argos.wityu.fund;dinslips.se;kalkulator-oszczednosci.pl;wurmpower.at;drugdevice.org;foretprivee.ca;nurturingwisdom.com;funjose.org.gt;blgr.be;readberserk.com;lescomtesdemean.be;firstpaymentservices.com;malychanieruchomoscipremium.com;travelffeine.com;latribuessentielle.com;lusak.at;better.town;smessier.com;kafu.ch;ikads.org;id-et-d.fr;sanaia.com;prochain-voyage.net;edrcreditservices.nl;yassir.pro;gantungankunciakrilikbandung.com;moveonnews.com;bhwlawfirm.com;bigbaguettes.eu;edv-live.de;littlebird.salon;iyengaryogacharlotte.com;toponlinecasinosuk.co.uk;zonamovie21.net;caribdoctor.org;body-guards.it;calabasasdigest.com;elimchan.com;herbstfeststaefa.ch;thewellnessmimi.com;corola.es;pomodori-pizzeria.de;controldekk.com;lichencafe.com;lefumetdesdombes.com;seagatesthreecharters.com;copystar.co.uk;systemate.dk;alsace-first.com;webmaster-peloton.com;koko-nora.dk;jakekozmor.com;mousepad-direkt.de;iwelt.de;dirittosanitario.biz;precisionbevel.com;boulderwelt-muenchen-west.de;chatizel-paysage.fr;praxis-foerderdiagnostik.de;globedivers.wordpress.com;nosuchthingasgovernment.com;neuschelectrical.co.za;schmalhorst.de;mediaclan.info;ihr-news.jp;bunburyfreightservices.com.au;edelman.jp;backstreetpub.com;spsshomeworkhelp.com;lillegrandpalais.com;smithmediastrategies.com;enovos.de;loprus.pl;bsaship.com;importardechina.info;shhealthlaw.com;freie-baugutachterpraxis.de;maxadams.london;deprobatehelp.com;baylegacy.com;deltacleta.cat;financescorecard.com;maureenbreezedancetheater.org;plv.media;winrace.no;leoben.at;pawsuppetlovers.com;tuuliautio.fi;paradicepacks.com;1team.es;testcoreprohealthuk.com;broseller.com;iyahayki.nl;lorenacarnero.com;satyayoga.de;notmissingout.com;chavesdoareeiro.com;mezhdu-delom.ru;hugoversichert.de;jusibe.com;imaginado.de;craftleathermnl.com;sauschneider.info;atalent.fi;conexa4papers.trade;global-kids.info;serce.info.pl;agence-referencement-naturel-geneve.net;zimmerei-fl.de;augenta.com;fannmedias.com;villa-marrakesch.de;ulyssemarketing.com;x-ray.ca;schraven.de;bowengroup.com.au;sairaku.net;southeasternacademyofprosthodontics.org;modamilyon.com;pubweb.carnet.hr;alysonhoward.com;sahalstore.com;triactis.com;panelsandwichmadrid.es;xn--vrftet-pua.biz;adoptioperheet.fi;miriamgrimm.de;filmstreamingvfcomplet.be;kostenlose-webcams.com;deoudedorpskernnoordwijk.nl;live-your-life.jp;mardenherefordshire-pc.gov.uk;instatron.net;mirjamholleman.nl;euro-trend.pl;kojima-shihou.com;nuzech.com;basisschooldezonnewijzer.nl;quemargrasa.net;actecfoundation.org;gamesboard.info;podsosnami.ru;extensionmaison.info;retroearthstudio.com;polzine.net;hmsdanmark.dk;linnankellari.fi;schoellhammer.com;elpa.se;mooreslawngarden.com;rozemondcoaching.nl;lenreactiv-shop.ru;uranus.nl;advokathuset.dk;ora-it.de;love30-chanko.com;smartypractice.com;rebeccarisher.com;cafemattmeera.com;bargningavesta.se;www1.proresult.no;rhinosfootballacademy.com;polychromelabs.com;notsilentmd.org;makeflowers.ru;zimmerei-deboer.de;ccpbroadband.com;iwr.nl;wychowanieprzedszkolne.pl;greenpark.ch;bimnapratica.com;lachofikschiet.nl;memaag.com;parking.netgateway.eu;tanzschule-kieber.de;antiaginghealthbenefits.com;simulatebrain.com;digi-talents.com;hairnetty.wordpress.com;samnewbyjax.com;helikoptervluchtnewyork.nl;devlaur.com;cimanchesterescorts.co.uk;houseofplus.com;rushhourappliances.com;pelorus.group;kedak.de;lapmangfpt.info.vn;pivoineetc.fr;marchand-sloboda.com;anybookreader.de;markelbroch.com;celularity.com;rafaut.com;unim.su;latestmodsapks.com;thedresserie.com;bigasgrup.com;slimidealherbal.com;phantastyk.com;thailandholic.com;tophumanservicescourses.com;aakritpatel.com;navyfederalautooverseas.com;wien-mitte.co.at;forestlakeuca.org.au;sporthamper.com;psnacademy.in;michaelsmeriglioracing.com;jbbjw.com;colorofhorses.com;iqbalscientific.com;cleliaekiko.online;stemplusacademy.com;effortlesspromo.com;microcirc.net;mbfagency.com;theduke.de;drinkseed.com;troegs.com;peterstrobos.com;consultaractadenacimiento.com;huissier-creteil.com;geoffreymeuli.com;skanah.com;despedidascostablanca.es;alten-mebel63.ru;theadventureedge.com;profectis.de;mepavex.nl;rimborsobancario.net;pasvenska.se;tampaallen.com;symphonyenvironmental.com;videomarketing.pro;pickanose.com;licor43.de;aniblinova.wordpress.com;ventti.com.ar;hhcourier.com;buymedical.biz;oncarrot.com;nachhilfe-unterricht.com;mapawood.com;vox-surveys.com;milsing.hr;sotsioloogia.ee;nativeformulas.com;kirkepartner.dk;partnertaxi.sk;visiativ-industry.fr;transliminaltribe.wordpress.com;chefdays.de;cursosgratuitosnainternet.com;faronics.com;d2marketing.co.uk;lapinlviasennus.fi;miraclediet.fun;bristolaeroclub.co.uk;jameskibbie.com;songunceliptv.com;baronloan.org;idemblogs.com;eglectonk.online;christinarebuffetcourses.com;bastutunnan.se;blogdecachorros.com;finde-deine-marke.de;platformier.com;antenanavi.com;vanswigchemdesign.com;gporf.fr;pmc-services.de;atmos-show.com;danholzmann.com;itelagen.com;transportesycementoshidalgo.es;gymnasedumanagement.com;siluet-decor.ru;gasbarre.com;milltimber.aberdeen.sch.uk;tinkoff-mobayl.ru;expandet.dk;rumahminangberdaya.com;polymedia.dk;newyou.at;zenderthelender.com;artallnightdc.com;tomaso.gr;centrospgolega.com;sweering.fr;tux-espacios.com;ecopro-kanto.com;spacecitysisters.org;bierensgebakkramen.nl;all-turtles.com;coffreo.biz;tandartspraktijkheesch.nl;vietlawconsultancy.com;deko4you.at;tennisclubetten.nl;extraordinaryoutdoors.com;crowcanyon.com;classycurtainsltd.co.uk;apolomarcas.com;verytycs.com;manijaipur.com;veybachcenter.de;falcou.fr;associationanalytics.com;beautychance.se;pocket-opera.de;christ-michael.net;vdberg-autoimport.nl;4net.guru;finediningweek.pl;stampagrafica.es;naturalrapids.com;ussmontanacommittee.us;beaconhealthsystem.org;upplandsspar.se;tradiematepro.com.au;oneplusresource.org;maasreusel.nl;aodaichandung.com;campus2day.de;burkert-ideenreich.de;you-bysia.com.au;mediaacademy-iraq.org;xtptrack.com;eaglemeetstiger.de;mountaintoptinyhomes.com;stemenstilte.nl;noskierrenteria.com;ivfminiua.com;biapi-coaching.fr;art2gointerieurprojecten.nl;corendonhotels.com;ditog.fr;kadesignandbuild.co.uk;abogadosaccidentetraficosevilla.es;camsadviser.com;limassoldriving.com;worldhealthbasicinfo.com;kojinsaisei.info;schmalhorst.de;bigler-hrconsulting.ch;girlillamarketing.com;xn--rumung-bua.online;naturstein-hotte.de;agence-chocolat-noir.com;stormwall.se;collaborativeclassroom.org;baptisttabernacle.com;streamerzradio1.site;mooglee.com;smart-light.co.uk;fitovitaforum.com;c2e-poitiers.com;igrealestate.com;wari.com.pe;takeflat.com;logopaedie-blomberg.de;mrsplans.net;mooshine.com;humanityplus.org;otsu-bon.com;onlyresultsmarketing.com;interactcenter.org;ungsvenskarna.se;35-40konkatsu.net;zzyjtsgls.com;spectrmash.ru;tenacitytenfold.com;torgbodenbollnas.se;drnice.de;lightair.com;huesges-gruppe.de;promalaga.es;paulisdogshop.de;hotelsolbh.com.br;julis-lsa.de;myteamgenius.com;darnallwellbeing.org.uk;refluxreducer.com;educar.org;kuntokeskusrok.fi;truenyc.co;comparatif-lave-linge.fr;frontierweldingllc.com;autodemontagenijmegen.nl;spylista.com;allfortheloveofyou.com;ilso.net;corona-handles.com;micahkoleoso.de;fairfriends18.de;haremnick.com;ecoledansemulhouse.fr;blewback.com;macabaneaupaysflechois.com;osterberg.fi;surespark.org.uk;stupbratt.no;hokagestore.com;mirkoreisser.de;tomoiyuma.com;tigsltd.com;manifestinglab.com;glennroberts.co.nz;hardinggroup.com;zso-mannheim.de;yousay.site;dublikator.com;oneheartwarriors.at;pointos.com;kenhnoithatgo.com;ausbeverage.com.au;testzandbakmetmening.online;grupocarvalhoerodrigues.com.br;werkkring.nl;hotelzentral.at;vibethink.net;123vrachi.ru;allure-cosmetics.at;mrxermon.de;bloggyboulga.net;bouldercafe-wuppertal.de;sobreholanda.com;smogathon.com;beyondmarcomdotcom.wordpress.com;wraithco.com;bookspeopleplaces.com;montrium.com;webcodingstudio.com;lucidinvestbank.com;ncs-graphic-studio.com;stingraybeach.com;aglend.com.au;lecantou-coworking.com;tongdaifpthaiphong.net;solerluethi-allart.ch;coursio.com;otto-bollmann.de;madinblack.com;vibehouse.rw;bridgeloanslenders.com;erstatningsadvokaterne.dk;resortmtn.com;socstrp.org;pier40forall.org;ostheimer.at;quickyfunds.com;aminaboutique247.com;jobcenterkenya.com;jenniferandersonwriter.com;marcuswhitten.site;mediaplayertest.net;irinaverwer.com;stoeberstuuv.de;lebellevue.fr;the-virtualizer.com;outcomeisincome.com;gonzalezfornes.es;kunze-immobilien.de;myhealth.net.au;helenekowalsky.com;xn--fn-kka.no;withahmed.com;simplyblessedbykeepingitreal.com;havecamerawilltravel2017.wordpress.com;muamuadolls.com;balticdentists.com;mank.de;croftprecision.co.uk;jandaonline.com;datacenters-in-europe.com;gw2guilds.org;raschlosser.de;geekwork.pl;pv-design.de;opatrovanie-ako.sk;ausair.com.au;commonground-stories.com;parebrise-tla.fr;vloeren-nu.nl;conasmanagement.de;dlc.berlin;liveottelut.com;4youbeautysalon.com;lykkeliv.net;adultgamezone.com;hexcreatives.co;citymax-cr.com;portoesdofarrobo.com;patrickfoundation.net;tonelektro.nl;atozdistribution.co.uk;urclan.net;evergreen-fishing.com;body-armour.online;nsec.se;autopfand24.de;syndikat-asphaltfieber.de;yourobgyn.net;vihannesporssi.fi;new.devon.gov.uk;teczowadolina.bytom.pl;antonmack.de;dpo-as-a-service.com;pogypneu.sk;creative-waves.co.uk;htchorst.nl;xn--fnsterputssollentuna-39b.se;norpol-yachting.com;parkstreetauto.net;sloverse.com;candyhouseusa.com;tsklogistik.eu;smejump.co.th;diversiapsicologia.es;unetica.fr;drfoyle.com;cranleighscoutgroup.org;dekkinngay.com;n1-headache.com;amerikansktgodis.se;evangelische-pfarrgemeinde-tuniberg.de;fransespiegels.nl;coastalbridgeadvisors.com;qualitaetstag.de;kath-kirche-gera.de;alhashem.net;schutting-info.nl;2ekeus.nl;berlin-bamboo-bikes.org;minipara.com;blood-sports.net;milestoneshows.com;physiofischer.de;ontrailsandboulevards.com;babcockchurch.org;healthyyworkout.com;plantag.de;krcove-zily.eu;mylolis.com;fax-payday-loans.com;praxis-management-plus.de;smokeysstoves.com;longislandelderlaw.com;calxplus.eu;mountsoul.de;dubscollective.com;luckypatcher-apkz.com;epwritescom.wordpress.com;fundaciongregal.org;klusbeter.nl;jobmap.at;oldschoolfun.net;abl1.net;labobit.it;romeguidedvisit.com;carrybrands.nl;people-biz.com;blossombeyond50.com;theclubms.com;whittier5k.com;jolly-events.com;kisplanning.com.au;rostoncastings.co.uk;ravensnesthomegoods.com;nhadatcanho247.com;vetapharma.fr;hihaho.com;tulsawaterheaterinstallation.com;purposeadvisorsolutions.com;faizanullah.com;directwindowco.com;herbayupro.com;pay4essays.net;work2live.de;stoneys.ch;webhostingsrbija.rs;lange.host;baustb.de;psa-sec.de;hushavefritid.dk;lloydconstruction.com;ra-staudte.de;mbxvii.com;tecnojobsnet.com;starsarecircular.org;twohourswithlena.wordpress.com;stoeferlehalle.de;merzi.info;garage-lecompte-rouen.fr;hypozentrum.com;nestor-swiss.ch;thomasvicino.com;kmbshipping.co.uk;denovofoodsgroup.com;planchaavapor.net;dr-pipi.de;qlog.de;lynsayshepherd.co.uk;aco-media.nl;abogadoengijon.es;bestbet.com;liliesandbeauties.org;norovirus-ratgeber.de;thee.network;stacyloeb.com;bundabergeyeclinic.com.au;sandd.nl;americafirstcommittee.org;milanonotai.it;kevinjodea.com;easytrans.com.au;westdeptfordbuyrite.com;carriagehousesalonvt.com;operaslovakia.sk;corelifenutrition.com;hashkasolutindo.com;compliancesolutionsstrategies.com;edgewoodestates.org;mastertechengineering.com;pinkexcel.com;cnoia.org;aprepol.com;rieed.de;katketytaanet.fi;lascuola.nl;assurancesalextrespaille.fr;paymybill.guru;xoabigail.com;ligiercenter-sachsen.de;answerstest.ru;airconditioning-waalwijk.nl;pixelarttees.com;freie-gewerkschaften.de;dnepr-beskid.com.ua;eco-southafrica.com;dutchcoder.nl;iphoneszervizbudapest.hu;allentownpapershow.com;bingonearme.org;summitmarketingstrategies.com;completeweddingkansas.com;wolf-glas-und-kunst.de;employeesurveys.com;scenepublique.net;monark.com;seitzdruck.com;alvinschwartz.wordpress.com;knowledgemuseumbd.com;spd-ehningen.de;boosthybrid.com.au;launchhubl.com;revezlimage.com;dontpassthepepper.com;petnest.ir;associacioesportivapolitg.cat;12starhd.online;jerling.de;kaotikkustomz.com;sarbatkhalsafoundation.org;solinegraphic.com;skiltogprint.no;craigmccabe.fun;puertamatic.es;mylovelybluesky.com;run4study.com;pierrehale.com;cactusthebrand.com;101gowrie.com;nicoleaeschbachorg.wordpress.com;architekturbuero-wagner.net;mindpackstudios.com;vitavia.lt;bouncingbonanza.com;lukeshepley.wordpress.com;igfap.com;bockamp.com;levihotelspa.fi;exenberger.at;tinyagency.com;familypark40.com;alfa-stroy72.com;boompinoy.com;mdacares.com;architecturalfiberglass.org;slupetzky.at;sinal.org;qualitus.com;deepsouthclothingcompany.com;groupe-frayssinet.fr;synlab.lt;kamienny-dywan24.pl;ilcdover.com;humancondition.com;insigniapmg.com;arteservicefabbro.com;team-montage.dk;iviaggisonciliegie.it;austinlchurch.com;rehabilitationcentersinhouston.net;zervicethai.co.th;vickiegrayimages.com;ziegler-praezisionsteile.de;crediacces.com;comarenterprises.com;courteney-cox.net;trapiantofue.it;space.ua;odiclinic.org;noesis.tech;urmasiimariiuniri.ro;8449nohate.org;xltyu.com;kikedeoliveira.com;remcakram.com;degroenetunnel.com;strandcampingdoonbeg.com;haar-spange.com;pmcimpact.com;ceid.info.tr;gemeentehetkompas.nl;stopilhan.com;dareckleyministries.com;sportverein-tambach.de;ivivo.es;braffinjurylawfirm.com;pcprofessor.com;bordercollie-nim.nl;hrabritelefon.hr;ctrler.cn;makeitcount.at;foryourhealth.live;seproc.hn;ianaswanson.com;nijaplay.com;brandl-blumen.de;lubetkinmediacompanies.com;ouryoungminds.wordpress.com;micro-automation.de;apprendrelaudit.com;securityfmm.com;geisterradler.de;morawe-krueger.de;nmiec.com;sla-paris.com;figura.team;vitalyscenter.es;jvanvlietdichter.nl;crosspointefellowship.church;handi-jack-llc.com;femxarxa.cat;wsoil.com.sg;xlarge.at;groupe-cets.com;admos-gleitlager.de;liikelataamo.fi;sevenadvertising.com;nancy-informatique.fr;ateliergamila.com;stefanpasch.me;wacochamber.com;aurum-juweliere.de;hatech.io;centuryrs.com;ilive.lt;fensterbau-ziegler.de;zflas.com;thefixhut.com;goodgirlrecovery.com;botanicinnovations.com;saxtec.com;tips.technology;smalltownideamill.wordpress.com;pt-arnold.de;tarotdeseidel.com;bildungsunderlebnis.haus;brevitempore.net;imadarchid.com;sportiomsportfondsen.nl;digivod.de;darrenkeslerministries.com;smhydro.com.pl;echtveilig.nl;schlafsack-test.net;galserwis.pl;eraorastudio.com;faroairporttransfers.net;connectedace.com;pcp-nc.com;jyzdesign.com;suncrestcabinets.ca;offroadbeasts.com;teresianmedia.org;greenfieldoptimaldentalcare.com;thomas-hospital.de;embracinghiscall.com;ralister.co.uk;rosavalamedahr.com;quizzingbee.com;richard-felix.co.uk;sipstroysochi.ru;todocaracoles.com;shiftinspiration.com;campusoutreach.org;bodyforwife.com;katiekerr.co.uk;sportsmassoren.com;trystana.com;ino-professional.ru;slashdb.com;selfoutlet.com;personalenhancementcenter.com;proudground.org;walkingdeadnj.com;d1franchise.com;anthonystreetrimming.com;forskolorna.org;brawnmediany.com;uimaan.fi;journeybacktolife.com;pferdebiester.de;kao.at;asteriag.com;hvccfloorcare.com;parks-nuernberg.de;div-vertriebsforschung.de;centromarysalud.com;asiluxury.com;chrissieperry.com;verbisonline.com;onlybacklink.com;radaradvies.nl;daklesa.de;sagadc.com;waveneyrivercentre.co.uk;mytechnoway.com;fitnessbazaar.com;fibrofolliculoma.info;fayrecreations.com;maryloutaylor.com;whyinterestingly.ru;maratonaclubedeportugal.com;maineemploymentlawyerblog.com;kosterra.com;blumenhof-wegleitner.at;punchbaby.com;wmiadmin.com;bxdf.info;harveybp.com;vermoote.de;johnsonfamilyfarmblog.wordpress.com;plastidip.com.ar;autofolierung-lu.de;highimpactoutdoors.net;cwsitservices.co.uk;hairstylesnow.site;mymoneyforex.com;victoriousfestival.co.uk;farhaani.com;web.ion.ag;simoneblum.de;carolinepenn.com;blacksirius.de;trackyourconstruction.com;naturavetal.hr;heliomotion.com;rollingrockcolumbia.com;judithjansen.com;poultrypartners.nl;mirjamholleman.nl;baumkuchenexpo.jp;insidegarage.pl;irishmachineryauctions.com;intecwi.com;porno-gringo.com;penco.ie;jacquin-maquettes.com;anteniti.com;hebkft.hu;ftlc.es;dutchbrewingcoffee.com;behavioralmedicinespecialists.com;socialonemedia.com;cirugiauretra.es;c-a.co.in;nokesvilledentistry.com;chandlerpd.com;aunexis.ch;gmto.fr;berliner-versicherungsvergleich.de;jsfg.com;vesinhnha.com.vn;joyeriaorindia.com;greenko.pl;cerebralforce.net;rota-installations.co.uk;presseclub-magdeburg.de;yamalevents.com;renergysolution.com;roygolden.com;verifort-capital.de;delawarecorporatelaw.com;jiloc.com;icpcnj.org;1kbk.com.ua;noixdecocom.fr;entopic.com;hellohope.com;flexicloud.hk;danielblum.info;thaysa.com;mdk-mediadesign.de;nataschawessels.com;smale-opticiens.nl;charlesreger.com;kaliber.co.jp;almosthomedogrescue.dog;reddysbakery.com;waynela.com;ahouseforlease.com;binder-buerotechnik.at;happyeasterimages.org;dr-tremel-rednitzhembach.de;mikeramirezcpa.com;zweerscreatives.nl;dramagickcom.wordpress.com;commercialboatbuilding.com;argenblogs.com.ar;heurigen-bauer.at;ogdenvision.com;gadgetedges.com;izzi360.com;turkcaparbariatrics.com;spargel-kochen.de;pridoxmaterieel.nl;heidelbergartstudio.gallery;ftf.or.at;kaminscy.com;filmvideoweb.com;meusharklinithome.wordpress.com;xn--thucmctc-13a1357egba.com;tstaffing.nl;abogadosadomicilio.es;igorbarbosa.com;homesdollar.com;ncuccr.org;caffeinternet.it;abogados-en-alicante.es;evologic-technologies.com;oslomf.no;desert-trails.com;gastsicht.de;nvwoodwerks.com;slwgs.org;vorotauu.ru;lionware.de;bodyfulls.com;myhostcloud.com;amylendscrestview.com;bptdmaluku.com;bogdanpeptine.ro;perbudget.com;strategicstatements.com;simpliza.com;innote.fi;365questions.org;sanyue119.com;walter-lemm.de;cuppacap.com;teknoz.net;layrshift.eu;blog.solutionsarchitect.guru;parkcf.nl;themadbotter.com;upmrkt.co;modelmaking.nl;nandistribution.nl;ledmes.ru;coding-marking.com;sachnendoc.com;thedad.com;mercantedifiori.com;artotelamsterdam.com;plotlinecreative.com;bauertree.com;woodleyacademy.org;dw-css.de;leda-ukraine.com.ua;destinationclients.fr;jasonbaileystudio.com;cheminpsy.fr;devstyle.org;kindersitze-vergleich.de;live-con-arte.de;bee4win.com;fiscalsort.com;jeanlouissibomana.com;huehnerauge-entfernen.de;eadsmurraypugh.com;fotoscondron.com;DupontSellsHomes.com;brigitte-erler.com;imperfectstore.com;shonacox.com;nacktfalter.de;devok.info;esope-formation.fr;mariposapropaneaz.com;sw1m.ru;mrtour.site;hannah-fink.de;bafuncs.org;kampotpepper.gives;ampisolabergeggi.it;cuspdental.com;philippedebroca.com;abitur-undwieweiter.de;hoteledenpadova.it;tanciu.com;delchacay.com.ar;cortec-neuro.com;theshungiteexperience.com.au;deschl.net;biortaggivaldelsa.com;fitnessingbyjessica.com;dsl-ip.de;officehymy.com;shadebarandgrillorlando.com;bargningharnosand.se;mmgdouai.fr;daniel-akermann-architektur-und-planung.ch;xn--logopdie-leverkusen-kwb.de;buroludo.nl;ymca-cw.org.uk;executiveairllc.com;allamatberedare.se;servicegsm.net;kingfamily.construction;nakupunafoundation.org;henricekupper.com;shsthepapercut.com;lbcframingelectrical.com;ladelirante.fr;clos-galant.com;dr-seleznev.com;siliconbeach-realestate.com;tanzprojekt.com;fatfreezingmachines.com;kamahouse.net;gratispresent.se;softsproductkey.com;marathonerpaolo.com;gopackapp.com;manutouchmassage.com;marketingsulweb.com;craigvalentineacademy.com;catholicmusicfest.com;gaiam.nl;woodworkersolution.com;pasivect.co.uk;cyntox.com;advizewealth.com;y-archive.com;saarland-thermen-resort.com;fizzl.ru;oemands.dk;mrsfieldskc.com;levdittliv.se;rksbusiness.com;sexandfessenjoon.wordpress.com;first-2-aid-u.com;simpkinsedwards.co.uk;the-domain-trader.com;rocketccw.com;celeclub.org;urist-bogatyr.ru;lapinvihreat.fi;ecpmedia.vn;zieglerbrothers.de;piajeppesen.dk;joseconstela.com;carlosja.com;real-estate-experts.com;toreria.es;analiticapublica.es;kariokids.com;leeuwardenstudentcity.nl;psc.de;tetinfo.in;ai-spt.jp;homng.net;em-gmbh.ch;trulynolen.co.uk;oceanastudios.com;csgospeltips.se;luxurytv.jp;abuelos.com;birnam-wood.com;theletter.company;bbsmobler.se;restaurantesszimmer.de;insp.bi;besttechie.com;autodujos.lt;chaotrang.com;galleryartfair.com;321play.com.hk;saka.gr;tandartspraktijkhartjegroningen.nl;steampluscarpetandfloors.com;waermetauscher-berechnen.de;sterlingessay.com;justinvieira.com;waywithwords.net;shiresresidential.com;naswrrg.org;spinheal.ru;slimani.net;modestmanagement.com;triggi.de;cityorchardhtx.com;narcert.com",
  "net": false,
  "svc": [
    "veeam",
    "memtas",
    "sql",
    "backup",
    "vss",
    "sophos",
    "svc$",
    "mepocs"
  ],
  "nbody": "LQAtAC0APQA9AD0AIABXAGUAbABjAG8AbQBlAC4AIABBAGcAYQBpAG4ALgAgAD0APQA9AC0ALQAtAA0ACgANAAoAWwAtAF0AIABXAGgAYQB0AHMAIABIAGEAcABQAGUAbgA/ACAAWwAtAF0ADQAKAA0ACgBZAG8AdQByACAAZgBpAGwAZQBzACAAYQByAGUAIABlAG4AYwByAHkAcAB0AGUAZAAsACAAYQBuAGQAIABjAHUAcgByAGUAbgB0AGwAeQAgAHUAbgBhAHYAYQBpAGwAYQBiAGwAZQAuACAAWQBvAHUAIABjAGEAbgAgAGMAaABlAGMAawAgAGkAdAA6ACAAYQBsAGwAIABmAGkAbABlAHMAIABvAG4AIAB5AG8AdQByACAAcwB5AHMAdABlAG0AIABoAGEAcwAgAGUAeAB0AGUAbgBzAGkAbwBuACAAewBFAFgAVAB9AC4ADQAKAEIAeQAgAHQAaABlACAAdwBhAHkALAAgAGUAdgBlAHIAeQB0AGgAaQBuAGcAIABpAHMAIABwAG8AcwBzAGkAYgBsAGUAIAB0AG8AIAByAGUAYwBvAHYAZQByACAAKAByAGUAcwB0AG8AcgBlACkALAAgAGIAdQB0ACAAeQBvAHUAIABuAGUAZQBkACAAdABvACAAZgBvAGwAbABvAHcAIABvAHUAcgAgAGkAbgBzAHQAcgB1AGMAdABpAG8AbgBzAC4AIABPAHQAaABlAHIAdwBpAHMAZQAsACAAeQBvAHUAIABjAGEAbgB0ACAAcgBlAHQAdQByAG4AIAB5AG8AdQByACAAZABhAHQAYQAgACgATgBFAFYARQBSACkALgANAAoADQAKAFsAKwBdACAAVwBoAGEAdAAgAGcAdQBhAHIAYQBuAHQAZQBlAHMAPwAgAFsAKwBdAA0ACgANAAoASQB0AHMAIABqAHUAcwB0ACAAYQAgAGIAdQBzAGkAbgBlAHMAcwAuACAAVwBlACAAYQBiAHMAbwBsAHUAdABlAGwAeQAgAGQAbwAgAG4AbwB0ACAAYwBhAHIAZQAgAGEAYgBvAHUAdAAgAHkAbwB1ACAAYQBuAGQAIAB5AG8AdQByACAAZABlAGEAbABzACwAIABlAHgAYwBlAHAAdAAgAGcAZQB0AHQAaQBuAGcAIABiAGUAbgBlAGYAaQB0AHMALgAgAEkAZgAgAHcAZQAgAGQAbwAgAG4AbwB0ACAAZABvACAAbwB1AHIAIAB3AG8AcgBrACAAYQBuAGQAIABsAGkAYQBiAGkAbABpAHQAaQBlAHMAIAAtACAAbgBvAGIAbwBkAHkAIAB3AGkAbABsACAAbgBvAHQAIABjAG8AbwBwAGUAcgBhAHQAZQAgAHcAaQB0AGgAIAB1AHMALgAgAEkAdABzACAAbgBvAHQAIABpAG4AIABvAHUAcgAgAGkAbgB0AGUAcgBlAHMAdABzAC4ADQAKAFQAbwAgAGMAaABlAGMAawAgAHQAaABlACAAYQBiAGkAbABpAHQAeQAgAG8AZgAgAHIAZQB0AHUAcgBuAGkAbgBnACAAZgBpAGwAZQBzACwAIABZAG8AdQAgAHMAaABvAHUAbABkACAAZwBvACAAdABvACAAbwB1AHIAIAB3AGUAYgBzAGkAdABlAC4AIABUAGgAZQByAGUAIAB5AG8AdQAgAGMAYQBuACAAZABlAGMAcgB5AHAAdAAgAG8AbgBlACAAZgBpAGwAZQAgAGYAbwByACAAZgByAGUAZQAuACAAVABoAGEAdAAgAGkAcwAgAG8AdQByACAAZwB1AGEAcgBhAG4AdABlAGUALgANAAoASQBmACAAeQBvAHUAIAB3AGkAbABsACAAbgBvAHQAIABjAG8AbwBwAGUAcgBhAHQAZQAgAHcAaQB0AGgAIABvAHUAcgAgAHMAZQByAHYAaQBjAGUAIAAtACAAZgBvAHIAIAB1AHMALAAgAGkAdABzACAAZABvAGUAcwAgAG4AbwB0ACAAbQBhAHQAdABlAHIALgAgAEIAdQB0ACAAeQBvAHUAIAB3AGkAbABsACAAbABvAHMAZQAgAHkAbwB1AHIAIAB0AGkAbQBlACAAYQBuAGQAIABkAGEAdABhACwAIABjAGEAdQBzAGUAIABqAHUAcwB0ACAAdwBlACAAaABhAHYAZQAgAHQAaABlACAAcAByAGkAdgBhAHQAZQAgAGsAZQB5AC4AIABJAG4AIABwAHIAYQBjAHQAaQBjAGUAIAAtACAAdABpAG0AZQAgAGkAcwAgAG0AdQBjAGgAIABtAG8AcgBlACAAdgBhAGwAdQBhAGIAbABlACAAdABoAGEAbgAgAG0AbwBuAGUAeQAuAA0ACgANAAoAWwArAF0AIABIAG8AdwAgAHQAbwAgAGcAZQB0ACAAYQBjAGMAZQBzAHMAIABvAG4AIAB3AGUAYgBzAGkAdABlAD8AIABbACsAXQANAAoADQAKAFkAbwB1ACAAaABhAHYAZQAgAHQAdwBvACAAdwBhAHkAcwA6AA0ACgANAAoAMQApACAAWwBSAGUAYwBvAG0AbQBlAG4AZABlAGQAXQAgAFUAcwBpAG4AZwAgAGEAIABUAE8AUgAgAGIAcgBvAHcAcwBlAHIAIQANAAoAIAAgAGEAKQAgAEQAbwB3AG4AbABvAGEAZAAgAGEAbgBkACAAaQBuAHMAdABhAGwAbAAgAFQATwBSACAAYgByAG8AdwBzAGUAcgAgAGYAcgBvAG0AIAB0AGgAaQBzACAAcwBpAHQAZQA6ACAAaAB0AHQAcABzADoALwAvAHQAbwByAHAAcgBvAGoAZQBjAHQALgBvAHIAZwAvAA0ACgAgACAAYgApACAATwBwAGUAbgAgAG8AdQByACAAdwBlAGIAcwBpAHQAZQA6ACAAaAB0AHQAcAA6AC8ALwBhAHAAbABlAGIAegB1ADQANwB3AGcAYQB6AGEAcABkAHEAawBzADYAdgByAGMAdgA2AHoAYwBuAGoAcABwAGsAYgB4AGIAcgA2AHcAawBlAHQAZgA1ADYAbgBmADYAYQBxADIAbgBtAHkAbwB5AGQALgBvAG4AaQBvAG4ALwB7AFUASQBEAH0ADQAKAA0ACgAyACkAIABJAGYAIABUAE8AUgAgAGIAbABvAGMAawBlAGQAIABpAG4AIAB5AG8AdQByACAAYwBvAHUAbgB0AHIAeQAsACAAdAByAHkAIAB0AG8AIAB1AHMAZQAgAFYAUABOACEAIABCAHUAdAAgAHkAbwB1ACAAYwBhAG4AIAB1AHMAZQAgAG8AdQByACAAcwBlAGMAbwBuAGQAYQByAHkAIAB3AGUAYgBzAGkAdABlAC4AIABGAG8AcgAgAHQAaABpAHMAOgANAAoAIAAgAGEAKQAgAE8AcABlAG4AIAB5AG8AdQByACAAYQBuAHkAIABiAHIAbwB3AHMAZQByACAAKABDAGgAcgBvAG0AZQAsACAARgBpAHIAZQBmAG8AeAAsACAATwBwAGUAcgBhACwAIABJAEUALAAgAEUAZABnAGUAKQANAAoAIAAgAGIAKQAgAE8AcABlAG4AIABvAHUAcgAgAHMAZQBjAG8AbgBkAGEAcgB5ACAAdwBlAGIAcwBpAHQAZQA6ACAAaAB0AHQAcAA6AC8ALwBkAGUAYwBvAGQAZQByAC4AcgBlAC8AewBVAEkARAB9AA0ACgANAAoAVwBhAHIAbgBpAG4AZwA6ACAAcwBlAGMAbwBuAGQAYQByAHkAIAB3AGUAYgBzAGkAdABlACAAYwBhAG4AIABiAGUAIABiAGwAbwBjAGsAZQBkACwAIAB0AGgAYQB0AHMAIAB3AGgAeQAgAGYAaQByAHMAdAAgAHYAYQByAGkAYQBuAHQAIABtAHUAYwBoACAAYgBlAHQAdABlAHIAIABhAG4AZAAgAG0AbwByAGUAIABhAHYAYQBpAGwAYQBiAGwAZQAuAA0ACgANAAoAVwBoAGUAbgAgAHkAbwB1ACAAbwBwAGUAbgAgAG8AdQByACAAdwBlAGIAcwBpAHQAZQAsACAAcAB1AHQAIAB0AGgAZQAgAGYAbwBsAGwAbwB3AGkAbgBnACAAZABhAHQAYQAgAGkAbgAgAHQAaABlACAAaQBuAHAAdQB0ACAAZgBvAHIAbQA6AA0ACgBLAGUAeQA6AA0ACgANAAoADQAKAHsASwBFAFkAfQANAAoADQAKAA0ACgAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ADQAKAA0ACgAhACEAIQAgAEQAQQBOAEcARQBSACAAIQAhACEADQAKAEQATwBOACcAVAAgAHQAcgB5ACAAdABvACAAYwBoAGEAbgBnAGUAIABmAGkAbABlAHMAIABiAHkAIAB5AG8AdQByAHMAZQBsAGYALAAgAEQATwBOACcAVAAgAHUAcwBlACAAYQBuAHkAIAB0AGgAaQByAGQAIABwAGEAcgB0AHkAIABzAG8AZgB0AHcAYQByAGUAIABmAG8AcgAgAHIAZQBzAHQAbwByAGkAbgBnACAAeQBvAHUAcgAgAGQAYQB0AGEAIABvAHIAIABhAG4AdABpAHYAaQByAHUAcwAgAHMAbwBsAHUAdABpAG8AbgBzACAALQAgAGkAdABzACAAbQBhAHkAIABlAG4AdABhAGkAbAAgAGQAYQBtAGEAZwBlACAAbwBmACAAdABoAGUAIABwAHIAaQB2AGEAdABlACAAawBlAHkAIABhAG4AZAAsACAAYQBzACAAcgBlAHMAdQBsAHQALAAgAFQAaABlACAATABvAHMAcwAgAGEAbABsACAAZABhAHQAYQAuAA0ACgAhACEAIQAgACEAIQAhACAAIQAhACEADQAKAE8ATgBFACAATQBPAFIARQAgAFQASQBNAEUAOgAgAEkAdABzACAAaQBuACAAeQBvAHUAcgAgAGkAbgB0AGUAcgBlAHMAdABzACAAdABvACAAZwBlAHQAIAB5AG8AdQByACAAZgBpAGwAZQBzACAAYgBhAGMAawAuACAARgByAG8AbQAgAG8AdQByACAAcwBpAGQAZQAsACAAdwBlACAAKAB0AGgAZQAgAGIAZQBzAHQAIABzAHAAZQBjAGkAYQBsAGkAcwB0AHMAKQAgAG0AYQBrAGUAIABlAHYAZQByAHkAdABoAGkAbgBnACAAZgBvAHIAIAByAGUAcwB0AG8AcgBpAG4AZwAsACAAYgB1AHQAIABwAGwAZQBhAHMAZQAgAHMAaABvAHUAbABkACAAbgBvAHQAIABpAG4AdABlAHIAZgBlAHIAZQAuAA0ACgAhACEAIQAgACEAIQAhACAAIQAhACEAAAA=",
  "nname": "{EXT}-readme.txt",
  "exp": false,
  "img": "QQBsAGwAIABvAGYAIAB5AG8AdQByACAAZgBpAGwAZQBzACAAYQByAGUAIABlAG4AYwByAHkAcAB0AGUAZAAhAA0ACgANAAoARgBpAG4AZAAgAHsARQBYAFQAfQAtAHIAZQBhAGQAbQBlAC4AdAB4AHQAIABhAG4AZAAgAGYAbwBsAGwAbwB3ACAAaQBuAHMAdAB1AGMAdABpAG8AbgBzAAAA",
  "arn": false,
  "rdmcnt": 0
}
```

The malware has a separate function to parse each field in the configuration.


![alt text](/uploads/revil7.PNG)

*Figure 7: Setting up parsing functions.*


Below is the list of configuration fields that this sample uses and their description.


| Field   | Description |
| -------- | ----------- |
| **pk** | Campaign public key |
| **pid** | Affiliate ID |
| **sub** |  Campaign ID |
| **dbg** |  Enable debug mode |
| **wht** |  Whitelist:<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- ***fld***: Folder names<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- ***fls***: File names<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- ***ext***: Extensions|
| **prc** |  Processes to kill |
| **svc** |  Services to stop |
| **dmn** | Network domains |
| **net** |  Enable network communication |
| **nbody** |  Base64-encoded ransom note |
| **nname** |  Ransom note filename |
| **img** |  Base64-encoded ransom wallpaper image |
| **et** |  Encryption type:<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- ***0***: Full encryption<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- ***1***: Fast Encryption<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- ***2***: Chunking by **\<spsize\>** megabytes |
| **spsize** | Number of megabytes to skip between each chunk when encryption type is 2 |
| **arn** | Enable persistence |
| **rdmcnt** | Total number of folders to drop ransom note |
| **exp** | Enable privilege escalation |

## Command-line Arguments

**REvil** can run with or without command-line arguments. 

Below is the list of arguments that can be supplied by the operator:


| Argument   | Description |
| -------- | ----------- |
| **-nolan** | Disable encryption for network drives and resources |
| **-nolocal** | Disable encryption for drive shares |
| **-path \<target\>** |  Path to a directory to be encrypted specifically  |
| **-silent** |  Disable service and process killing|
| **-smode** |  Enable safemode reboot |
| **-fast** |  Override encryption type to fast encryption |
| **-full** |  Override encryption type to full encryption |


## Generate Victim Information

### I. Victim Secret Key

Prior to encryption, the malware randomly generates a public-private key pair for the victim, which is later used to generate the **Salsa20** keys to encrypt files.

Because the system private key is crucial in file decryption, **REvil** encrypts it using the campaign public key (extracted from the configuration) and a hard-coded operator public key.


The key encryption algorithm works by generating a public-private key pair and producing a shared-secret between the generated private key and the provided public key.

The malware encrypts the data with AES using the shared-secret as the key and the generated public key as the IV. The public key is appended at the end of the encrypted data.

To decrypt, the operator can provide their private key to generate the same shared secret with the public key at the end of the data and decrypt it using **AES**.

![alt text](/uploads/revil8.PNG)

*Figure 8: Key encryption algorithm.*


The campaign-encrypted system private key, operator-encrypted system private key, campaign public key, and system public key are then written to these registry keys.


```
- SOFTWARE\BlackLivesMatter\Ed7: campaign public key
- SOFTWARE\BlackLivesMatter\QIeQ: system public key
- SOFTWARE\BlackLivesMatter\96Ia6: campaign-encrypted system private key
- SOFTWARE\BlackLivesMatter\Ucr1RB: operator-encrypted system private key
```

![alt text](/uploads/revil9.PNG)

*Figure 9: Generating system secret key.*


### II. Victim ID

The victim ID is a string of 16 hex characters generated from the CRC checksums of the system's volume serial number and the CPU ID.

![alt text](/uploads/revil10.PNG)

*Figure 10: Generating victim ID.*

### III. Encrypted File Extension

The final encrypted file extension is a string of 5 random characters concatenated by the string from the **nname** field in the configuration.


This file extension is added to the value of the registry key **SOFTWARE\BlackLivesMatter\wJWsTYE** and to the extension whitelist.


![alt text](/uploads/revil11.PNG)

*Figure 11: Generating encrypted file extension.*


### IV. Full Victim Information Buffer


The generated victim information buffer is a string in JSON form that contains the following fields.

| Field   | Description |
| -------- | ----------- |
| **ver** | Ransomware sample's version (hard-coded) |
| **pid** | Affiliate ID extracted from configuration |
| **sub** |  Campaign ID extracted from configuration  |
| **pk** |  Base64-encoded campaign public key extracted from configuration |
| **uid** |  Victim ID |
| **sk** |  Base64-encoded system private key |
| **unm** |  Victim's username |
| **net** | Computer's name |
| **grp** | Victim's domain from **SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Domain** (Default: **WORKGROUP**) |
| **lng** |  Locale name  |
| **bro** | Language check result |
| **os** |  Product name |
| **bit** |  Processor architecture |
| **dsk** |  Base64-encoded HDD information |
| **ext** |  Encrypted file extension |


This buffer is encrypted using a hard-coded **Curve25519** public key in memory and assigned to the value of the registry key **SOFTWARE\BlackLivesMatter\JmfOBvhb**.


![alt text](/uploads/revil12.PNG)

*Figure 12: Generating victim information buffer.*


## Building Ransom Note

The ransom note content is extracted from the **nbody** field from the configuration.

The malware replaces its **{UID}** tag with the generated victim ID, **{KEY}** tag with the **base64** string of the encrypted victim information buffer, and **{EXT}** with the encrypted file extension.

![alt text](/uploads/revil13.PNG)

*Figure 13: Building ransom note's content.*

## Building Ransom Wallpaper Image

The ransom wallpaper image is extracted from the **img** field from the configuration.

The malware replaces its **{UID}** tag with the generated victim ID, **{KEY}** tag with the **base64** string of the encrypted victim information buffer, **{EXT}** with the encrypted file extension, **{USERNAME}** with the victim's username, and **{NOTENAME}** with the ransom note's filename.


![alt text](/uploads/revil14.PNG)

*Figure 14: Building ransom wallpaper image.*

During post-encryption, the malware changes the background of the victim's machine to this wallpaper image.

## Language Check
If the value of the **dbg** field in the configuration is **false**, the malware checks for the system's language and keyboard layout to see if it should encrypt this system or not.

First, it checks if the default UI language is in the language whitelist.

![alt text](/uploads/revil15.PNG)

*Figure 15: Checking whitelist language.*

Next, it checks if the system's keyboard layout is in the keyboard layout whitelist.

![alt text](/uploads/revil16.PNG)

*Figure 16: Checking whitelist keyboard layout.*


If the check succeeds, the malware terminates immediately. This is pretty standard for Russian ransomware, and I don't think I need to go into details about [why this code block is here ;)](https://twitter.com/campuscodi/status/1387953199680741376)


## Safemood Reboot

If the command-line argument **-smode** is provided, the malware attempts to force the system to reboot into safe mode in order to gain more priviledge to execute itself.


First, it calls **GetSystemMetrics** to check if the machine is started with a normal boot. If it is, the malware sets the user account's name to **"DTrump4ever"**.

It also sets the following registry values:

```
- SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon: "1"
- SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\DefaultUserName: "DTrump4ever"
- SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\DefaultPassword: "DTrump4ever"
```

This ultimately sets the default credentials to **"DTrump4ever"** and enable automatic admin logon upon reboot.

![alt text](/uploads/revil17.PNG)

*Figure 17: Setting new logon credentials.*


Next, it sets the value of the registry key **SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\\*AstraZeneca** to its own executable path to automatically launch itself upon reboot.

Then, if the Windows OS is pre-Vista, it sets the value of the registry key **SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\\*MarineLePen** to **"bootcfg /raw /fastdetect /id 1"** and executes **"bootcfg /raw /a /safeboot:network /id 1"** using **WinExec**.

If the Windows OS is Vista or above, it sets the value of the registry key **SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\\*MarineLePen** to **"bcdedit /deletevalue {current} safeboot"** and executes **"bcdedit /set {current} safeboot network"** using **WinExec**.

This ensures that the OS will always boot into safe mode.

![alt text](/uploads/revil18.PNG)

*Figure 18: Configuring OS to boot into safe mode.*

Finally, if the malware has enough priviledge, it forces rebooting the system with **NtShutdownSystem**. If not, it forces rebooting with **ExitWindowsEx**.

![alt text](/uploads/revil19.PNG)

*Figure 19: Configuring OS to boot into safe mode.*


## Run-Once Mutex

The malware checks if there is another instance of itself running by checking if the mutex **"Global\422BE415-4098-BB75-3BD9-3E62EE8E8423"** already exists using **CreateMutex**.

If there is another instance, the malware terminates itself.

![alt text](/uploads/revil20.PNG)

*Figure 20: Checking run-once mutex.*

## Priviledge Escalation

If the value of the **exp** field in the configuration is **true**, the malware attempts to escalate and launch itself with higher priviledge.

First, it checks if it's currently running with restricted priviledge by using **GetTokenInformation** to get information on the current process's token elevation type and identifer authority.

If it is, it calls **ShellExecuteExW** to execute a **runas** command to launch the malware with the same provided command-line arguments. Since the **runas** command launches the application with admin credentials, this ensures the malware will have higher priviledge than it currently does.

![alt text](/uploads/revil21.PNG)

*Figure 21: Priviledge escalation.*


## Pre-Encryption Setup

First, the malware calls **SHEmptyRecycleBinW** to empty the Recycle Bin folder and **SetPriorityClass** to set the priority class of the current process to **ABOVE_NORMAL_PRIORITY_CLASS**.

Next, it calls **WinExec** to execute the following command to enable network discovery on the system.

``` powershell
netsh advfirewall firewall set rule group="Network Discovery" new enable=Yes
```

![alt text](/uploads/revil22.PNG)

*Figure 22: Pre-Encryption setup.*

## Persistence

If the value of the **arn** field in the configuration is **true**, the malware establishes persistence through registry.

It sets the value of the registry key **SOFTWARE\Microsoft\Windows\CurrentVersion\Run\t32mMaunsR** to its current executable path to automatically launch itself when the system boots up.

![alt text](/uploads/revil23.PNG)

*Figure 23: Establishing persistence.*


## Terminating Services and Processes through WMI

If the command-line argument **-silent** is not provided, the malware attempts to terminate all services and processes in the lists from the **prc** and **svc** fields through WMI.

First, it calls **CoCreateInstance** to create an **IWbemLocator** object using the CLSID *{4590F811-1D3A-11D0-891F-00AA004B2E24}*.

The malware calls the **IWbemLocator::ConnectServer** method to connect with the local **ROOT\CIMV2** namespace and obtain the pointer to an **IWbemServices** object.

![alt text](/uploads/revil24.PNG)

*Figure 24: Connecting to ROOT\CIMV2 to get IWbemServices object.*

Next, it calls **CoCreateInstance** to create an **IUnsecuredApartment** object using the CLSID *{49bd2028-1523-11d1-ad79-00c04fd8fdff}*.

Using this **IUnsecuredApartment** object, the malware calls the **IUnsecuredApartment::CreateObjectStub** function to create an object forwarder sink to handle receiving asynchronous calls from **Windows Management**. This registers a function to terminate processes and services received from asynchronous calls.

![alt text](/uploads/revil25.PNG)

*Figure 25: Creating an object forwarder sink to handle processes and services.*


Using the **IWbemServices** object, the malware calls **IWbemServices::ExecNotificationQueryAsync** to execute these two **WQL** commands, which pipes the process and service query results to the registered creation event handler.

``` SQL
SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'
SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Service'
```

![alt text](/uploads/revil26.PNG)

*Figure 26: Executing query WQL commands.*


The handler calls the **IWbemClassObject::Get** function to retrieve the **TargetInstance**, **__CLASS**, and **__PATH** properties of the received object.

It checks if the object's class is **Win32_Process**, then it calls the **IWbemClassObject::GetMethod** function to get the **IWbemClassObject** object of the **GetOwner** function.

Using this **GetOwner** object, it calls the **IWbemClassObject::Get** function to retrieve the user, domain, and name of the process. It terminates the process if the process's name is in the process-to-kill list from the **prc** field.

![alt text](/uploads/revil27.PNG)

*Figure 27: Retrieving the process's name through WMI.*

To terminate the process, the malware calls the **IWbemServices::GetObject** function to retrieve an **IWbemClassObject** object for **Win32_Process**. 

It then calls **IWbemClassObject::Get** to retrieve the path of the process's executable and **IWbemClassObject::GetMethod** to get an **IWbemClassObject** object for the **Terminate** function.


It calls **IWbemClassObject::Put** to add a terminate reason to the **Terminate** object before calling **IWbemServices::ExecMethod** to execute the **Terminate** method and kill the process.

![alt text](/uploads/revil28.PNG)

*Figure 28: Terminating process through WMI.*


If the object's class is **Win32_Service** instead, the malware calls the **IWbemClassObject::Get** function to get the name and state of the service. It stops the service if the service name is in the service-to-kill list from the **svc** field and the service state is **"Running"**.


![alt text](/uploads/revil29.PNG)

*Figure 29: Retrieving the service's name and state through WMI.*

To stop the service, the malware calls **IWbemClassObject::Get** to retrieve the path of the service's executable and **IWbemServices::ExecMethod** to execute the **StopService** method to stop the service.

![alt text](/uploads/revil30.PNG)

*Figure 30: Stopping service through WMI.*


## Terminating Services through Service Control Manager

The malware calls **OpenSCManagerW** to get a service control manager handle for active services. 

It then calls **EnumServicesStatusExW** to enumerate Win32 services that are active and terminates any service whose name is in the service-to-kill list from the **svc** field.

![alt text](/uploads/revil31.PNG)

*Figure 31: Enumerating services using Service Control Manager.*


To fully terminate the target service, the malware first terminates all of its depedent services.

By calling **EnumDependentServicesW** and **OpenServiceW**, it retrieves the Service Control Manager handle for each depedent service and recursively terminates its depedent services.

The malware calls **ControlService** to send the **SERVICE_CONTROL_STOP** control code to each depedent service and continuously waits until the service is fully stopped.

![alt text](/uploads/revil32.PNG)

*Figure 32: Recursively stopping all depdent services of the target service.*

Afterward, the malware sends the **SERVICE_CONTROL_STOP** control code to the main service to stop it and calls **DeleteService** to mark the specified service for deletion from the Service Control Manager database.

![alt text](/uploads/revil33.PNG)

*Figure 33: Stop and delete the target service.*


## Terminating Processes

The malware calls **CreateToolhelp32Snapshot**, **Process32FirstW**, and **Process32NextW** to enumerate through all running processes and executes the process terminating function on them.

![alt text](/uploads/revil34.PNG)

*Figure 34: Enumerating processes.*

The process terminating function terminates each process using **TerminateProcess** if its name is in the process-to-kill list from the **prc** field.

![alt text](/uploads/revil35.PNG)

*Figure 35: Terminating target process.*

## Deleting Shadow Copies

The malware calls **CoCreateInstance** to create an **IWbemContext** object using the CLSID *{674B6698-EE92-11D0-AD71-00C04FD8FDFF}*.

If the system architecture is **x64**, it calls the **IWbemContext::SetValue** function to set the value of **"__ProviderArchitecture"** to **64**.

It then calls **CoCreateInstance** to create an **IWbemLocator** object using the CLSID *{4590F811-1D3A-11D0-891F-00AA004B2E24}*.

The malware calls the **IWbemLocator::ConnectServer** method to connect with the local **ROOT\CIMV2** namespace and obtain the pointer to an **IWbemServices** object.


![alt text](/uploads/revil36.PNG)

*Figure 36: Connecting to ROOT\CIMV2 to get IWbemServices object (again).*

Next, it calls **IWbemServices::ExecQuery** to execute the WQL query below to get the **IEnumWbemClassObject** object for querying shadow copies.

``` SQL
select * from Win32_ShadowCopy
```

The malware calls **IEnumWbemClassObject::Next** to enumerate through all shadow copies on the system, **IEnumWbemClassObject::Get** to get the ID of each shadow copies, and **IWbemServices::DeleteInstance** to delete them.

![alt text](/uploads/revil37.PNG)

*Figure 37: Deleting shadow copies through WMI.*


## File Encryption

### Multithreading setup

**REvil** uses multithreading with I/O completion port to communicate between the main thread and the worker threads to speed up encryption.

Prior to encryption, the malware allocates memory for a shared structure that is used by threads to communicate with each other.

Below is the layout of this structure.

``` c
struct THREAD_STRUCT
{
  HANDLE HeapHandle;
  HANDLE IOCompletionPort;
  DWORD threadCount;
  LONG unused; // these fields are left unused for some reason.
  LONG unused2; // Or maybe I'm just blind lmao
  HANDLE fileHandle;
  DWORD fileName;
  LONG unused3;
  LONG lowerFileEncryptedSize;
  LONG higherFileEncryptedSize;
  BYTE CAMPAIGN_ENCRYPTED_PRIV_SYS_KEY[88];
  BYTE OPERATOR_ENCRYPTED_PRIV_SYS_KEY[88];
  BYTE filePublicKey[32];
  BYTE Salsa20Nonce[8];
  DWORD filePublicKeyCRC32Hash;
  DWORD encryptionType;
  DWORD SPSIZE;
  DWORD Salsa20XorStream;
  BYTE Salsa20Key[64];
  DWORD threadCurrentState;
  DWORD threadNextState;
  DWORD fileBufferReadLength;
  DWORD fileDataBuffer;
};
```

The malware creates the heap handle and IO Completion Port handle and adds them to this structure before spawning children threads to encrypt files.


![alt text](/uploads/revil38.PNG)

*Figure 38: Setting up thread struct.*

Next, it spawns children threads that waits to receive files from the main thread to encrypt. 

The number of children threads is double the number of processors on the system, and these threads' priority is set to **THREAD_PRIORITY_HIGHEST**.

![alt text](/uploads/revil39.PNG)

*Figure 39: Spawning children threads.*

### Main Thread Traversal

#### I. Checking Directory Name

When the malware first encounters a directory, it first calls a function to check the directory's name.

The path to the directory is valid to be encrypted when it contains both **"program files"** and **sql** or if the directory name is not in the folder name whitelist.

![alt text](/uploads/revil40.PNG)

*Figure 40: Checking directory name.*


#### II. Dropping Ransom Note

If the directory is valid to encrypt, the main malware thread calls a function to drop the ransom note in it.

This function first tries to create a file called **"tmp"** in the directory to check if it has priviledge to access and create files.

If it fails, **REvil** calls **SetEntriesInAclW** to creates a new access control list by merging access control information into the process's existing ACL structure. This helps it gain the priviledge to access files in the directory.

![alt text](/uploads/revil41.PNG)

*Figure 41: Modifying ACL to gain access rights to directory.*


Then, the malware creates the ransom note file in the directory and writes the ransom note's content to it.

![alt text](/uploads/revil42.PNG)

*Figure 42: Dropping ransom note.*


However, the ransom note is only created in a set number of directories specified by the **rdmcnt** field. The ransom note counter is reset to zero every time the malware begins encrypting a new local or remote drive.

![alt text](/uploads/revil43.PNG)

*Figure 43: Full function to drop ransom note.*

#### III. Traversal

The malware uses **FindFirstFileW** and **FindNextFileW** to traverse through the target folder. 


**REvil** does not encrypt the file/folder it finds if its name is **"."**, **".."** or if it has an associated reparse point (folder) or is a symbolic link (file).

If the malware finds a folder, it calls the [function to check the folder's name](#i-checking-directory-name) before adding it to the folder-to-encrypt-list and dropping a ransom note inside.

This list is a buffer in memory that contains a list of folders for the malware to go through and encrypt, and it eliminates the need of using recursive traversal.


![alt text](/uploads/revil44.PNG)

*Figure 44: Processing sub-folder.*


If the malware finds a file, it calls a function to check the filename and extension.

A file is valid to be encrypted when the filename does not contain **"ntuser"**, is not in the filename whitelist, and its extension is not in the extension whitelist.

![alt text](/uploads/revil45.PNG)

*Figure 45: Checking filename and extension.*


If the file is to be encrypted, the malware calls a function to set up encryption keys before signalling the children threads to encrypt it.

#### IV. Pre-Encryption File Setup

For each encrypted file, a 232-byte file footer is appended to the end of the file at the end of the encryption phase. This file footer contains the chunk between the **CAMPAIGN_ENCRYPTED_PRIV_SYS_KEY** field and the **Salsa20XorStream** field in the **THREAD_STRUCT** structure.

``` c
struct FILE_FOOTER
{
  BYTE CAMPAIGN_ENCRYPTED_PRIV_SYS_KEY[88];
  BYTE OPERATOR_ENCRYPTED_PRIV_SYS_KEY[88];
  BYTE filePublicKey[32];
  BYTE Salsa20Nonce[8];
  DWORD filePublicKeyCRC32Hash;
  DWORD encryptionType;
  DWORD SPSIZE;
  DWORD Salsa20XorStream;
};
```

When the malware sets up the file for encryption, it checks if the file is not already encrypted. 

This is done by manually checking the file footer by computing the CRC32 checksum of the **filePublicKey** field and compare it to the **filePublicKeyCRC32Hash** field.

If the checksum does not match, the file is not encrypted, and the malware can proceed to encrypt it.

![alt text](/uploads/revil46.PNG)

*Figure 46: Checking if file is encrypted.*

For each encrypted file, a **THREAD_STRUCT** structure is allocated to storing data about that file.

Next, the malware determines the length of the buffer that file data can be read into and encrypted. The size of this buffer is set to **0x100000** bytes, but if the file size is smaller than that, then the size of this buffer is set to the file size.

![alt text](/uploads/revil47.PNG)

*Figure 47: Setting file buffer length.*

Next, the malware creates the file and populates the **fileHandle**, **fileName**, **threadCount**, **lowerFileEncryptedSize**, and **higherFileEncryptedSize** fields in the structure.

![alt text](/uploads/revil48.PNG)

*Figure 48: Setting file buffer length.*

If retrieving the file handle fails, the malware attempts to terminate services that are using the file.

It calls **OpenSCManagerW** to retrieve a handle to the Service Control Manager for active services. It also calls **RmStartSession** and **RmRegisterResources** to register the file resource to the Restart Manager session.

![alt text](/uploads/revil49.PNG)

*Figure 49: Initializing Service Control Manager and Restart Manager.*


Next, the malware calls **RmGetList** to retrieve and enumerate the list of applications that are restricting the file being accessed. 

If the application is a Windows service, the malware calls the [function earlier](#terminating-services-through-service-control-manager) to terminate the service.

If the application's process ID is 4, the application is a critical service, or the process's executable is **"vmcompute.exe", "vmms.exe", "vmwp.exe", and "svchost.exe"**, the service is skipped and not terminated.

If the application does not fall into the conditions above, it's terminated by **TerminateProcess**.

![alt text](/uploads/revil50.PNG)

*Figure 50: Terminating services and processes that are using file.*

Finally, the main malware thread sets up the encryption keys in the file's **THREAD_STRUCT** structure.

First, the campaign-encrypted system private key and operator-encrypted system private key are written into the structure.

The malware then generates a **Curve25519** public-private key pair for the file. The file's private key is used to generate a shared-secret with the system public key, and the shared-secret is hashed using **SHA-3**.

The shared-secret hash is then used to generate the 32-byte **Salsa20** key for the file. The 8-byte **Salsa20** nonce is randomly generated. 

The file's public key is then hashed using **CRC32** and assigned to the structure's **filePublicKeyCRC32Hash** field.

The malware also encrypts a buffer with 4 null bytes and assigned that to the structure's **Salsa20XorStream** field. I'm not entirely sure what this is used for, but it's most likely to check if the **Salsa20** key is properly decrypted when the decryptor processes the file.

![alt text](/uploads/revil51.PNG)

*Figure 51: Setting up file encryption keys in the file's THREAD_STRUCT structure.*


### Children Thread Encryption

Children threads communicate with each other and the main thread using **GetQueuedCompletionStatus** and **PostQueuedCompletionStatus**.


Each thread constantly polls for an I/O completion packet from the main **THREAD_STRUCT** structure. The packet received from **GetQueuedCompletionStatus** contains an file's **THREAD_STRUCT** structure as well as the number of bytes to be read and encrypted.


This thread adds that number to the current file pointer in the file's structure before continuing to process the file.

![alt text](/uploads/revil52.PNG)

*Figure 52: Children thread polling for I/O packets to process file.*


The encryption process is divided into four states. The file's current state and next state is recorded in its **THREAD_STRUCT** structure.

![alt text](/uploads/revil53.PNG)

*Figure 53: File encryption states.*


#### I. State 1: Reading File

The first state reads a set amount of bytes specified by the **fileBufferReadLength** field in the structure into the buffer at the **fileDataBuffer** field.

It sets the **threadCurrentState** field to 1 and the **threadNextState** to 2. If it reaches the end of file after calling **ReadFile**, the **threadNextState** field is set to 3.

![alt text](/uploads/revil54.PNG)

*Figure 54: State 1: Reading file.*

#### II. State 2. Encrypt and Write File

The second state encrypts the buffer at the **fileDataBuffer** field with **Salsa20**. 

It then moves the file pointer back to the start of the unencrypted part and overwrites that with the encrypted data.

![alt text](/uploads/revil56.PNG)

*Figure 55: State 2: Encrypting and writing file.*

The next state now depends on the encryption type. 

If the encryption type is 1 (Fast Encryption), then the next state is set to 3. This is because this encryption type only encrypts the first **0x100000** bytes of the file.

If the encryption type is 0 or 2, the next state is set to 1 to continue reading from file.

When the encryption type is 2 (chunking), the file pointer is calculated differently. The file pointer will be changed to jump ahead by a set number of megabytes specified by the **spsize** field to skip to the next chunk. If the data remained to be encrypted is less than the skipping size, the file pointer jumps to the end of the file.


![alt text](/uploads/revil55.PNG)

*Figure 56: State 2: Chunking.*


#### III. State 3. Write File Footer

The third state is executed only when the file encryption is finished.

If the encryption type is fast encryption, the file pointer is set to the end of the file.

Then, the file writes [the file footer](#pre-encryption-setup) in the file's **THREAD_STRUCT** structure to the end of the file. This file footer contains information that is used when decrypting files.


![alt text](/uploads/revil57.PNG)

*Figure 57: State 3: Writing file footer.*

During state 3, the next state is set to 4.

#### IV. State 4. Move File

This is the last state in the file encryption process. 

The malware appends the encrypted file extension to the filename and calls **MoveFileW** to move the encrypted file to this new filename.

Finally, it calls a function to free up the file's **THREAD_STRUCT** structure.

![alt text](/uploads/revil58.PNG)

*Figure 58: State 4: Moving file and cleaning up.*

### Network Shares Traversal

If the target path is a network path, the malware calls **NetShareEnum** to enumerate network shared resources on the system.

For each shared resource, after appending its name to the target path, the malware traverses and encrypts it using the same traversal function [above](#main-thread-traversal).

![alt text](/uploads/revil59.PNG)

*Figure 59: Shared resources traversal.*

### Drive Shares Traversal

If the command-line argument **-nolocal** is not provided, the malware attempts to encrypt all drive shares.

It enumerates through all drives on the system. If the drive type is **DRIVE_REMOVABLE** or **DRIVE_FIXED** or **DRIVE_REMOTE**, the malware traverses and encrypts using the same traversal function [above](#main-thread-traversal).

If the drive type is **DRIVE_FIXED** specifically, the malware calls **NetShareAdd** to share the drive's resource with the local system.

![alt text](/uploads/revil60.PNG)

*Figure 60: Drive shares traversal.*

### Network Drives and Resources Traversal

If the command-line argument **-nolan** is not provided, the malware attempts to encrypt all drive shares.

First, it calls **OpenProcess**, **OpenProcessToken**, and **DuplicateToken** to get an access token to duplicate that of an **explorer.exe** process.

It calls **CreateToolhelp32Snapshot**, **Thread32First**, and **Thread32Next** to enumerate through all running threads.

For all children threads running, the malware sets their thread token to the duplicate **explorer.exe** token.

![alt text](/uploads/revil61.PNG)

*Figure 61: Impersonating children threads as Explorer threads.*

The main thread itself also impersonates **explorer.exe** by calling **ImpersonateLoggedOnUser** on the **Explorer** process token.

![alt text](/uploads/revil62.PNG)

*Figure 62: Impersonating main thread as Explorer thread.*


It enumerates through all drives on the system. If the drive type is **DRIVE_REMOTE**, the malware traverses and encrypts using the same traversal function [above](#main-thread-traversal).

![alt text](/uploads/revil63.PNG)

*Figure 63: Network drives traversal.*

Next, it calls a recursive function to enumerate network resources at multiple enumeration scopes.

The malware calls **WNetEnumResourceW** to enumerate through network resources, and for each that is found, **REvil** recursively traverses through its resources until it has gone through all resources in the network.


For each of these resources, the malware traverses and encrypts using the same traversal function [above](#main-thread-traversal).


![alt text](/uploads/revil64.PNG)

*Figure 64: Enumerating and encrypting network resources.*


## Network Communication

If the value of the **net** field in the configuration is **true**, the malware sends the victim's information to network domains listed in the **dmn** field.

The malware calls the function to [generate the victim information buffer](#generate-victim-information) prior to establishing a connection to each domain.


For each domain, it builds an HTTPS URL in the form of **"https://\<domain\>//<random_string_1>//\<random_string_2\>//\<random_string_3\>.\<random_string_4\>"** where:

* **random_string_1** is randomly one of the strings in the list **["wp-content", "static", "content", "include", "uploads", "news", "data", "admin"]**.
* **random_string_2** is randomly one of the strings in the list **["images", "pictures", "image", "temp", "tmp", "graphic", "assets", "pics", "game"]**.
* **random_string_3** is a string with random lower-case characters with a random length between 1 and 10.
* **random_string_4** is randomly one of the strings in the list **["jpg", "png", "gif"]**


Next, it calls **WinHttpOpen** to retrieve a HTTP session handle with the following agent.

```
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.125 Safari/537.36
```

It then calls **WinHttpCrackUrl** to crack the generated URL into components and calls **WinHttpConnect** to establish a connection to the server.

![alt text](/uploads/revil65.PNG)

*Figure 65: Establishing connection to network domain.*

Next, it calls **WinHttpOpenRequest** to create an HTTP POST request handle. Using this handle, the malware sends the victim information to the domain through a **WinHttpOpenRequest** call.

![alt text](/uploads/revil66.PNG)

*Figure 66: Sending data to network domain.*

The server's response is received using **WinHttpReceiveResponse** and read into a buffer using a stream object that uses an HGLOBAL memory handle, but the malware doesn't do anything with this.


## Self-Deletion

After the encryption is finished and everything is cleaned up from memory, the malware deletes itself by calling **MoveFileExW** and providing a null pointer for the **lpNewFileName** parameter.

This registers the executable file to be deleted when the system restarts.

![alt text](/uploads/revil67.PNG)

*Figure 67: Self-Deletion.*

## File Decryption

Thanks to the extra work being put into its cryptography scheme, the operators have three different ways to decrypt files.

Because the shared-secret of the file private key and the system public key is used to generate the Salsa20 key to encrypt the file, the same key can be generated from the shared-secret of the file public key (located in the file footer) and the system private key.

As a result, the decryptor must have access to the system private key, and there are a three ways to retrieve this.

### I. Operator Key

Since the operator-encrypted system private key is in the file footer at the end of every encrypted file, the operator can decrypt the system private key using their operator private key.

Alternatively, they can ask the victim's to provide the operator-encrypted system private key from the value of the registry key **SOFTWARE\BlackLivesMatter\Ucr1RB**.

### II. Campaign Key
Since the campaign-encrypted system private key is in the file footer at the end of every encrypted file, the operator can decrypt the system private key using the campaign private key.

Alternatively, they can ask the victim's to provide the campaign-encrypted system private key from the value of the registry key **SOFTWARE\BlackLivesMatter\96Ia6**

### III. Decrypting the Victim Information Buffer

The [victim information buffer](#iv-full-victim-information-buffer) is encrypted using a hard-coded public key and embedded in the ransom note.

When the victim submits this encrypted buffer to the operator on their website, they can decrypt it using their own private key and base64-decode the system private key in the **sk** field.


## Personal Opinion
Probably the most well-engineered ransomware out there. Fancy crypto and threading, but an absolute pain in the ass to analyze.


## References
https://twitter.com/fwosar/status/1411281334870368260
https://gist.github.com/fwosar/a63e1249bfccb8395b961d3d780c0354
https://github.com/brainhub/SHA3IUF/blob/master/sha3.c
https://intel471.com/blog/revil-ransomware-as-a-service-an-analysis-of-a-ransomware-affiliate-operation
https://www.secureworks.com/research/revil-sodinokibi-ransomware
https://www.youtube.com/watch?v=R4xJou6JsIE

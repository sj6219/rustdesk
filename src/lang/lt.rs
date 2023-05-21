lazy_static::lazy_static! {
pub static ref T: std::collections::HashMap<&'static str, &'static str> =
    [
        ("Status", "Būsena"),
        ("Your Desktop", "Jūsų darbalaukis"),
        ("desk_tip", "Jūsų darbalaukis pasiekiamas naudojant šį ID ir slaptažodį"),
        ("Password", "Slaptažodis"),
        ("Ready", "Pasiruošęs"),
        ("Established", "Įsteigta"),
        ("connecting_status", "Prisijungiama prie RustDesk tinklo..."),
        ("Enable Service", "Įgalinti paslaugą"),
        ("Start Service", "Pradėti paslaugą"),
        ("Service is running", "Paslauga veikia"),
        ("Service is not running", "Paslauga neveikia"),
        ("not_ready_status", "Neprisijungęs. Patikrinkite ryšį."),
        ("Control Remote Desktop", "Nuotolinio darbalaukio valdymas"),
        ("Transfer File", "Perkelti failą"),
        ("Connect", "Prisijungti"),
        ("Recent Sessions", "Seansų istorija"),
        ("Address Book", "Adresų knyga"),
        ("Confirmation", "Patvirtinimas"),
        ("TCP Tunneling", "TCP tuneliavimas"),
        ("Remove", "Pašalinti"),
        ("Refresh random password", "Atnaujinti atsitiktinį slaptažodį"),
        ("Set your own password", "Nustatykite savo slaptažodį"),
        ("Enable Keyboard/Mouse", "Įgalinti klaviatūrą/pelę"),
        ("Enable Clipboard", "Įgalinti iškarpinę"),
        ("Enable File Transfer", "Įgalinti failų perdavimą"),
        ("Enable TCP Tunneling", "Įgalinti TCP tuneliavimą"),
        ("IP Whitelisting", "IP baltasis sąrašas"),
        ("ID/Relay Server", "ID / perdavimo serveris"),
        ("Import Server Config", "Importuoti serverio konfigūraciją"),
        ("Export Server Config", "Eksportuoti serverio konfigūraciją"),
        ("Import server configuration successfully", "Sėkmingai importuoti serverio konfigūraciją"),
        ("Export server configuration successfully", "Sėkmingai eksportuoti serverio konfigūraciją"),
        ("Invalid server configuration", "Netinkama serverio konfigūracija"),
        ("Clipboard is empty", "Iškarpinė tuščia"),
        ("Stop service", "Sustabdyti paslaugą"),
        ("Change ID", "Keisti ID"),
        ("Your new ID", "Jūsų naujasis ID"),
        ("length %min% to %max%", "ilgis %min% iki %max%"),
        ("starts with a letter", "prasideda raide"),
        ("allowed characters", "leistini simboliai"),
        ("id_change_tip", "Leidžiami tik simboliai a–z, A–Z, 0–9 ir _ (pabraukimas). Pirmoji raidė turi būti a-z, A-Z. Ilgis nuo 6 iki 16."),
        ("Website", "Interneto svetainė"),
        ("About", "Apie"),
        ("Slogan_tip", "Sukurta su siela šiame beprotiškame pasaulyje!"),
        ("Privacy Statement", "Privatumo pareiškimas"),
        ("Mute", "Nutildyti"),
        ("Build Date", "Sukūrimo data"),
        ("Version", "Versija"),
        ("Home", "Namai"),
        ("Audio Input", "Garso įvestis"),
        ("Enhancements", "Patobulinimai"),
        ("Hardware Codec", "Aparatinės įrangos paspartinimas"),
        ("Adaptive Bitrate", "Adaptyvusis pralaidumas"),
        ("ID Server", "ID serveris"),
        ("Relay Server", "Perdavimo serveris"),
        ("API Server", "API serveris"),
        ("invalid_http", "Turi prasidėti http:// arba https://"),
        ("Invalid IP", "Netinkamas IP"),
        ("Invalid format", "Neteisingas formatas"),
        ("server_not_support", "Serveris dar nepalaikomas"),
        ("Not available", "Nepasiekiamas"),
        ("Too frequent", "Per dažnai"),
        ("Cancel", "Atšaukti"),
        ("Skip", "Praleisti"),
        ("Close", "Uždaryti"),
        ("Retry", "Bandykite dar kartą"),
        ("OK", "GERAI"),
        ("Password Required", "Reikalingas slaptažodis"),
        ("Please enter your password", "Prašome įvesti savo slaptažodį"),
        ("Remember password", "Prisiminti slaptažodį"),
        ("Wrong Password", "Neteisingas slaptažodis"),
        ("Do you want to enter again?", "Ar norite įeiti dar kartą?"),
        ("Connection Error", "Ryšio klaida"),
        ("Error", "Klaida"),
        ("Reset by the peer", "Atmetė nuotolinis kompiuteris"),
        ("Connecting...", "Jungiamasi..."),
        ("Connection in progress. Please wait.", "Jungiamasi. Palaukite."),
        ("Please try 1 minute later", "Prašome pabandyti po 1 minutės"),
        ("Login Error", "Prisijungimo klaida"),
        ("Successful", "Sėkmingai"),
        ("Connected, waiting for image...", "Prisijungta, laukiama vaizdo..."),
        ("Name", "Vardas"),
        ("Type", "Tipas"),
        ("Modified", "Pakeista"),
        ("Size", "Dydis"),
        ("Show Hidden Files", "Rodyti paslėptus failus"),
        ("Receive", "Gauti"),
        ("Send", "Siųsti"),
        ("Refresh File", "Atnaujinti failą"),
        ("Local", "Vietinis"),
        ("Remote", "Nuotolinis"),
        ("Remote Computer", "Nuotolinis kompiuteris"),
        ("Local Computer", "Šis kompiuteris"),
        ("Confirm Delete", "Patvirtinti ištrynimą"),
        ("Delete", "Ištrinti"),
        ("Properties", "Ypatybės"),
        ("Multi Select", "Keli pasirinkimas"),
        ("Select All", "Pasirinkti viską"),
        ("Unselect All", "Atšaukti visų pasirinkimą"),
        ("Empty Directory", "Tuščias katalogas"),
        ("Not an empty directory", "Ne tuščias katalogas"),
        ("Are you sure you want to delete this file?", "Ar tikrai norite ištrinti šį failą?"),
        ("Are you sure you want to delete this empty directory?", "Ar tikrai norite ištrinti šį tuščią katalogą?"),
        ("Are you sure you want to delete the file of this directory?", "Ar tikrai norite ištrinti šio katalogo failą?"),
        ("Do this for all conflicts", "Taikyti visiems konfliktams"),
        ("This is irreversible!", "Tai negrįžtama!"),
        ("Deleting", "Ištrinama"),
        ("files", "failai"),
        ("Waiting", "Laukiu"),
        ("Finished", "Baigta"),
        ("Speed", "Greitis"),
        ("Custom Image Quality", "Tinkinta vaizdo kokybė"),
        ("Privacy mode", "Privatumo režimas"),
        ("Block user input", "Blokuoti naudotojo įvestį"),
        ("Unblock user input", "Atblokuoti naudotojo įvestį"),
        ("Adjust Window", "Koreguoti langą"),
        ("Original", "Originalas"),
        ("Shrink", "Susitraukti"),
        ("Stretch", "Ištempti"),
        ("Scrollbar", "Slinkties juosta"),
        ("ScrollAuto", "Automatinis slinkimas"),
        ("Good image quality", "Gera vaizdo kokybė"),
        ("Balanced", "Subalansuotas"),
        ("Optimize reaction time", "Optimizuoti reakcijos laiką"),
        ("Custom", "Tinkintas"),
        ("Show remote cursor", "Rodyti nuotolinį žymeklį"),
        ("Show quality monitor", "Rodyti kokybės monitorių"),
        ("Disable clipboard", "Išjungti mainų sritį"),
        ("Lock after session end", "Užrakinti pasibaigus seansui"),
        ("Insert", "Įdėti"),
        ("Insert Lock", "Įterpti užraktą"),
        ("Refresh", "Atnaujinti"),
        ("ID does not exist", "ID neegzistuoja"),
        ("Failed to connect to rendezvous server", "Nepavyko prisijungti prie susitikimo serverio"),
        ("Please try later", "Prašome pabandyti vėliau"),
        ("Remote desktop is offline", "Nuotolinis darbalaukis neprisijungęs"),
        ("Key mismatch", "Raktų neatitikimas"),
        ("Timeout", "Laikas baigėsi"),
        ("Failed to connect to relay server", "Nepavyko prisijungti prie perdavimo serverio"),
        ("Failed to connect via rendezvous server", "Nepavyko prisijungti per susitikimo serverį"),
        ("Failed to connect via relay server", "Nepavyko prisijungti per perdavimo serverį"),
        ("Failed to make direct connection to remote desktop", "Nepavyko tiesiogiai prisijungti prie nuotolinio darbalaukio"),
        ("Set Password", "Nustatyti slaptažodį"),
        ("OS Password", "OS slaptažodis"),
        ("install_tip", "Kai kuriais atvejais UAC gali priversti RustDesk netinkamai veikti nuotoliniame pagrindiniame kompiuteryje. Norėdami apeiti UAC, spustelėkite toliau esantį mygtuką, kad įdiegtumėte RustDesk į savo kompiuterį."),
        ("Click to upgrade", "Spustelėkite, jei norite atnaujinti"),
        ("Click to download", "Spustelėkite norėdami atsisiųsti"),
        ("Click to update", "Spustelėkite norėdami atnaujinti"),
        ("Configure", "Konfigūruoti"),
        ("config_acc", "Norėdami nuotoliniu būdu valdyti darbalaukį, turite suteikti RustDesk \"prieigos\" leidimus"),
        ("config_screen", "Norėdami nuotoliniu būdu pasiekti darbalaukį, turite suteikti RustDesk leidimus \"ekrano kopija\""),
        ("Installing ...", "Diegiama ..."),
        ("Install", "Diegti"),
        ("Installation", "Įdiegimas"),
        ("Installation Path", "Įdiegimo kelias"),
        ("Create start menu shortcuts", "Sukurti pradžios meniu sparčiuosius klavišus"),
        ("Create desktop icon", "Sukurti darbalaukio piktogramą"),
        ("agreement_tip", "Pradėdami diegimą sutinkate su licencijos sutarties sąlygomis"),
        ("Accept and Install", "Priimti ir įdiegti"),
        ("End-user license agreement", "Galutinio vartotojo licencijos sutartis"),
        ("Generating ...", "Generuojamas..."),
        ("Your installation is lower version.", "Jūsų įdiegta versija senesnė."),
        ("not_close_tcp_tip", "Naudodami tunelį neuždarykite šio lango"),
        ("Listening ...", "Laukimas..."),
        ("Remote Host", "Nuotolinis pagrindinis kompiuteris"),
        ("Remote Port", "Nuotolinis prievadas"),
        ("Action", "Veiksmas"),
        ("Add", "Papildyti"),
        ("Local Port", "Vietinis prievadas"),
        ("Local Address", "Vietinis adresas"),
        ("Change Local Port", "Keisti vietinį prievadą"),
        ("setup_server_tip", "Kad ryšys būtų greitesnis, nustatykite savo serverį"),
        ("Too short, at least 6 characters.", "Per trumpas, mažiausiai 6 simboliai."),
        ("The confirmation is not identical.", "Patvirtinimas nėra tapatus."),
        ("Permissions", "Leidimai"),
        ("Accept", "Priimti"),
        ("Dismiss", "Atmesti"),
        ("Disconnect", "Atjungti"),
        ("Allow using keyboard and mouse", "Leisti naudoti klaviatūrą ir pelę"),
        ("Allow using clipboard", "Leisti naudoti mainų sritį"),
        ("Allow hearing sound", "Leisti girdėti kompiuterio garsą"),
        ("Allow file copy and paste", "Leisti kopijuoti ir įklijuoti failus"),
        ("Connected", "Prisijungta"),
        ("Direct and encrypted connection", "Tiesioginis ir šifruotas ryšys"),
        ("Relayed and encrypted connection", "Perduotas ir šifruotas ryšys"),
        ("Direct and unencrypted connection", "Tiesioginis ir nešifruotas ryšys"),
        ("Relayed and unencrypted connection", "Perduotas ir nešifruotas ryšys"),
        ("Enter Remote ID", "Įveskite nuotolinio ID"),
        ("Enter your password", "Įveskite savo slaptažodį"),
        ("Logging in...", "Prisijungiama..."),
        ("Enable RDP session sharing", "Įgalinti RDP seansų bendrinimą"),
        ("Auto Login", "Automatinis prisijungimas"),
        ("Enable Direct IP Access", "Įgalinti tiesioginę IP prieigą"),
        ("Rename", "Pervardyti"),
        ("Space", "Erdvė"),
        ("Create Desktop Shortcut", "Sukurti nuorodą darbalaukyje"),
        ("Change Path", "Keisti kelią"),
        ("Create Folder", "Sukurti aplanką"),
        ("Please enter the folder name", "Įveskite aplanko pavadinimą"),
        ("Fix it", "Pataisyk tai"),
        ("Warning", "Įspėjimas"),
        ("Login screen using Wayland is not supported", "Prisijungimo ekranas naudojant Wayland nepalaikomas"),
        ("Reboot required", "Reikia paleisti iš naujo"),
        ("Unsupported display server", "Nepalaikomas rodymo serveris"),
        ("x11 expected", "reikalingas x11"),
        ("Port", "Prievadas"),
        ("Settings", "Nustatymai"),
        ("Username", "Vartotojo vardas"),
        ("Invalid port", "Netinkamas prievadas"),
        ("Closed manually by the peer", "Partneris atmetė prašymą prisijungti"),
        ("Enable remote configuration modification", "Įgalinti nuotolinį konfigūracijos modifikavimą"),
        ("Run without install", "Vykdyti be diegimo"),
        ("Connect via relay", "Prisijungti per relę"),
        ("Always connect via relay", "Visada prisijunkite per relę"),
        ("whitelist_tip", "Mane gali pasiekti tik baltajame sąraše esantys IP adresai"),
        ("Login", "Prisijungti"),
        ("Verify", "Patvirtinti"),
        ("Remember me", "Prisimink mane"),
        ("Trust this device", "Pasitikėk šiuo įrenginiu"),
        ("Verification code", "Patvirtinimo kodas"),
        ("verification_tip", "Aptiktas naujas įrenginys ir registruotu el. pašto adresu išsiųstas patvirtinimo kodas. Įveskite jį norėdami tęsti prisijungimą."),
        ("Logout", "Atsijungti"),
        ("Tags", "Žymos"),
        ("Search ID", "Paieškos ID"),
        ("whitelist_sep", "Atskirti kableliu, kabliataškiu, tarpu arba nauja eilute"),
        ("Add ID", "Pridėti ID"),
        ("Add Tag", "Pridėti žymą"),
        ("Unselect all tags", "Atšaukti visų žymų pasirinkimą"),
        ("Network error", "Tinklo klaida"),
        ("Username missed", "Prarastas vartotojo vardas"),
        ("Password missed", "Slaptažodis praleistas"),
        ("Wrong credentials", "Klaidingi kredencialai"),
        ("Edit Tag", "Redaguoti žymą"),
        ("Unremember Password", "Nebeprisiminti slaptažodžio"),
        ("Favorites", "Parankiniai"),
        ("Add to Favorites", "Įtraukti į parankinius"),
        ("Remove from Favorites", "Pašalinti iš parankinių"),
        ("Empty", "Tuščia"),
        ("Invalid folder name", "Neteisingas aplanko pavadinimas"),
        ("Socks5 Proxy", "Socks5 Proxy"),
        ("Hostname", "Pagrindinio kompiuterio pavadinimas"),
        ("Discovered", "Aptikta tinkle"),
        ("install_daemon_tip", "Norėdami, kad RustDesk startuotų automatiškai, turite ją įdiegti"),
        ("Remote ID", "Nuotolinis ID"),
        ("Paste", "Įklijuoti"),
        ("Paste here?", "Įklijuoti čia?"),
        ("Are you sure to close the connection?", "Ar tikrai norite atsijungti?"),
        ("Download new version", "Atsisiųsti naują versiją"),
        ("Touch mode", "Palietimo režimas"),
        ("Mouse mode", "Pelės režimas"),
        ("One-Finger Tap", "Palietimas vienu pirštu"),
        ("Left Mouse", "Kairysis pelės kl."),
        ("One-Long Tap", "Vienas palietimas"),
        ("Two-Finger Tap", "Palietimas dviem pirštais"),
        ("Right Mouse", "Dešinysis pelės kl."),
        ("One-Finger Move", "Vieno piršto judesys"),
        ("Double Tap & Move", "Dukart palieskite ir perkelkite"),
        ("Mouse Drag", "Pelės vilkimas"),
        ("Three-Finger vertically", "Trys pirštai vertikaliai"),
        ("Mouse Wheel", "Pelės ratukas"),
        ("Two-Finger Move", "Dviejų pirštų judesys"),
        ("Canvas Move", "Drobės perkėlimas"),
        ("Pinch to Zoom", "Suimkite, kad padidintumėte"),
        ("Canvas Zoom", "Drobės mastelis"),
        ("Reset canvas", "Atstatyti drobę"),
        ("No permission of file transfer", "Nėra leidimo perkelti failus"),
        ("Note", "Pastaba"),
        ("Connection", "Ryšys"),
        ("Share Screen", "Bendrinti ekraną"),
        ("Chat", "Pokalbis"),
        ("Total", "Iš viso"),
        ("items", "elementai"),
        ("Selected", "Pasirinkta"),
        ("Screen Capture", "Ekrano nuotrauka"),
        ("Input Control", "Įvesties valdymas"),
        ("Audio Capture", "Garso fiksavimas"),
        ("File Connection", "Failo ryšys"),
        ("Screen Connection", "Ekrano jungtis"),
        ("Do you accept?", "Ar sutinki?"),
        ("Open System Setting", "Atviros sistemos nustatymas"),
        ("How to get Android input permission?", "Kaip gauti Android įvesties leidimą?"),
        ("android_input_permission_tip1", "Kad nuotolinis įrenginys galėtų valdyti Android įrenginį pele arba liesti, turite leisti RustDesk naudoti \"Prieinamumo\" paslaugą."),
        ("android_input_permission_tip2", "Eikite į kitą sistemos nustatymų puslapį, suraskite \"Įdiegtos paslaugos\" ir įgalinkite \"RustDesk įvestis\" paslaugą."),
        ("android_new_connection_tip", "Gauta nauja užklausa tvarkyti dabartinį įrenginį."),
        ("android_service_will_start_tip", "Įgalinus ekrano fiksavimo paslaugą, kiti įrenginiai gali pateikti užklausą prisijungti prie to įrenginio."),
        ("android_stop_service_tip", "Uždarius paslaugą automatiškai bus uždaryti visi užmegzti ryšiai."),
        ("android_version_audio_tip", "Dabartinė Android versija nepalaiko garso įrašymo, atnaujinkite į Android 10 ar naujesnę versiją."),
        ("android_start_service_tip", "Spustelėkite [Paleisti paslaugą] arba įjunkite [Fiksuoti ekraną], kad paleistumėte ekrano bendrinimo paslaugą."),
        ("android_permission_may_not_change_tip", "Užmegztų ryšių leidimų keisti negalima, reikia prisijungti iš naujo."),
        ("Account", "Paskyra"),
        ("Overwrite", "Perrašyti"),
        ("This file exists, skip or overwrite this file?", "Šis failas egzistuoja, praleisti arba perrašyti šį failą?"),
        ("Quit", "Išeiti"),
        ("doc_mac_permission", "https://rustdesk.com/docs/en/manual/mac/"),
        ("Help", "Pagalba"),
        ("Failed", "Nepavyko"),
        ("Succeeded", "Pavyko"),
        ("Someone turns on privacy mode, exit", "Kažkas įjungė privatumo režimą, išeiti"),
        ("Unsupported", "Nepalaikomas"),
        ("Peer denied", "Atšaukė"),
        ("Please install plugins", "Įdiekite papildinius"),
        ("Peer exit", "Nuotolinis mazgas neveikia"),
        ("Failed to turn off", "Nepavyko išjungti"),
        ("Turned off", "Išjungti"),
        ("In privacy mode", "Privatumo režimas"),
        ("Out privacy mode", "Išėjimas iš privatumo režimo"),
        ("Language", "Kalba"),
        ("Keep RustDesk background service", "Palikti RustDesk fonine paslauga"),
        ("Ignore Battery Optimizations", "Ignoruoti akumuliatoriaus optimizavimą"),
        ("android_open_battery_optimizations_tip", "Eikite į kitą nustatymų puslapį"),
        ("Start on Boot", "Pradėti paleidžiant"),
        ("Start the screen sharing service on boot, requires special permissions", "Paleiskite ekrano bendrinimo paslaugą įkrovos metu, reikia specialių leidimų"),
        ("Connection not allowed", "Ryšys neleidžiamas"),
        ("Legacy mode", "Senasis režimas"),
        ("Map mode", "Žemėlapio režimas"),
        ("Translate mode", "Vertimo režimas"),
        ("Use permanent password", "Naudoti nuolatinį slaptažodį"),
        ("Use both passwords", "Naudoti abu slaptažodžius"),
        ("Set permanent password", "Nustatyti nuolatinį slaptažodį"),
        ("Enable Remote Restart", "Įgalinti nuotolinį paleidimą iš naujo"),
        ("Allow remote restart", "Leisti nuotolinio kompiuterio paleidimą iš naujo"),
        ("Restart Remote Device", "Paleisti nuotolinį kompiuterį iš naujo"),
        ("Are you sure you want to restart", "Ar tikrai norite paleisti iš naujo?"),
        ("Restarting Remote Device", "Nuotolinio įrenginio paleidimas iš naujo"),
        ("remote_restarting_tip", "Nuotolinis įrenginys paleidžiamas iš naujo. Uždarykite šį pranešimą ir po kurio laiko vėl prisijunkite naudodami nuolatinį slaptažodį."),
        ("Copied", "Nukopijuota"),
        ("Exit Fullscreen", "Išeiti iš pilno ekrano"),
        ("Fullscreen", "Per visą ekraną"),
        ("Mobile Actions", "Veiksmai mobiliesiems"),
        ("Select Monitor", "Pasirinkite monitorių"),
        ("Control Actions", "Valdymo veiksmai"),
        ("Display Settings", "Ekrano nustatymai"),
        ("Ratio", "Santykis"),
        ("Image Quality", "Vaizdo kokybė"),
        ("Scroll Style", "Slinkimo stilius"),
        ("Show Menubar", "Rodyti meniu juostą"),
        ("Hide Menubar", "Slėpti meniu juostą"),
        ("Direct Connection", "Tiesioginis ryšys"),
        ("Relay Connection", "Tarpinė jungtis"),
        ("Secure Connection", "Saugus ryšys"),
        ("Insecure Connection", "Nesaugus ryšys"),
        ("Scale original", "Pakeisti originalų mastelį"),
        ("Scale adaptive", "Pritaikomas mastelis"),
        ("General", "Bendra"),
        ("Security", "Sauga"),
        ("Theme", "Tema"),
        ("Dark Theme", "Tamsioji tema"),
        ("Light Theme", "Šviesi tema"),
        ("Dark", "Tamsi"),
        ("Light", "Šviesi"),
        ("Follow System", "Kaip sistemos"),
        ("Enable hardware codec", "Įgalinti"),
        ("Unlock Security Settings", "Atrakinti saugos nustatymus"),
        ("Enable Audio", "Įgalinti garsą"),
        ("Unlock Network Settings", "Atrakinti tinklo nustatymus"),
        ("Server", "Serveris"),
        ("Direct IP Access", "Tiesioginė IP prieiga"),
        ("Proxy", "Tarpinis serveris"),
        ("Apply", "Taikyti"),
        ("Disconnect all devices?", "Atjungti visus įrenginius?"),
        ("Clear", "Išvalyti"),
        ("Audio Input Device", "Garso įvestis"),
        ("Deny remote access", "Uždrausti nuotolinę prieigą"),
        ("Use IP Whitelisting", "Naudoti patikimą IP sąrašą"),
        ("Network", "Tinklas"),
        ("Enable RDP", "Įgalinti RDP"),
        ("Pin menubar", "Prisegti meniu juostą"),
        ("Unpin menubar", "Atsegti meniu juostą"),
        ("Recording", "Įrašymas"),
        ("Directory", "Katalogas"),
        ("Automatically record incoming sessions", "Automatiškai įrašyti įeinančius seansus"),
        ("Change", "Keisti"),
        ("Start session recording", "Pradėti seanso įrašinėjimą"),
        ("Stop session recording", "Sustabdyti seanso įrašinėjimą"),
        ("Enable Recording Session", "Įgalinti seanso įrašinėjimą"),
        ("Allow recording session", "Leisti seanso įrašinėjimą"),
        ("Enable LAN Discovery", "Įgalinti LAN aptikimą"),
        ("Deny LAN Discovery", "Neleisti LAN aptikimo"),
        ("Write a message", "Rašyti žinutę"),
        ("Prompt", "Užuomina"),
        ("Please wait for confirmation of UAC...", "Palaukite UAC patvirtinimo..."),
        ("elevated_foreground_window_tip", "Dabartinis nuotolinio darbalaukio langas reikalauja didesnių privilegijų, todėl laikinai neįmanoma naudoti pelės ir klaviatūros. Galite paprašyti nuotolinio vartotojo sumažinti dabartinį langą arba spustelėti aukščio mygtuką ryšio valdymo lange. Norint išvengti šios problemos ateityje, rekomenduojama programinę įrangą įdiegti nuotoliniame įrenginyje."),
        ("Disconnected", "Atsijungęs"),
        ("Other", "Kita"),
        ("Confirm before closing multiple tabs", "Patvirtinti prieš uždarant kelis skirtukus"),
        ("Keyboard Settings", "Klaviatūros nustatymai"),
        ("Full Access", "Pilna prieiga"),
        ("Screen Share", "Ekrano bendrinimas"),
        ("Wayland requires Ubuntu 21.04 or higher version.", "Wayland reikalauja Ubuntu 21.04 arba naujesnės versijos."),
        ("Wayland requires higher version of linux distro. Please try X11 desktop or change your OS.", "Wayland reikalinga naujesnės Linux Distro versijos. Išbandykite X11 darbalaukį arba pakeiskite OS."),
        ("JumpLink", "Peržiūra"),
        ("Please Select the screen to be shared(Operate on the peer side).", "Prašome pasirinkti ekraną, kurį norite bendrinti (veikiantį kitoje pusėje)."),
        ("Show RustDesk", "Rodyti RustDesk"),
        ("This PC", "Šis kompiuteris"),
        ("or", "arba"),
        ("Continue with", "Tęsti su"),
        ("Elevate", "Pakelti"),
        ("Zoom cursor", "Mastelio keitimo žymeklis"),
        ("Accept sessions via password", "Priimti seansus naudojant slaptažodį"),
        ("Accept sessions via click", "Priimti seansus spustelėjus"),
        ("Accept sessions via both", "Priimti seansus abiem variantais"),
        ("Please wait for the remote side to accept your session request...", "Palaukite, kol nuotolinė pusė priims jūsų seanso užklausą..."),
        ("One-time Password", "Vienkartinis slaptažodis"),
        ("Use one-time password", "Naudoti vienkartinį slaptažodį"),
        ("One-time password length", "Vienkartinio slaptažodžio ilgis"),
        ("Request access to your device", "Prašo leidimo valdyti jūsų įrenginį"),
        ("Hide connection management window", "Slėpti ryšio valdymo langą"),
        ("hide_cm_tip", "Leisti paslėpti didžiąją ir mažąją raidę, jei priimamos slaptažodžio sesijos arba naudojamas nuolatinis slaptažodis"),
        ("wayland_experiment_tip", "Wayland palaikymas yra eksperimentinis, naudokite X11, jei jums reikalingas automatinis prisijungimas."),
        ("Right click to select tabs", "Dešiniuoju pelės mygtuku spustelėkite, kad pasirinktumėte skirtukus"),
        ("Skipped", "Praleisti"),
        ("Add to Address Book", "Pridėti prie adresų knygos"),
        ("Group", "Grupė"),
        ("Search", "Paieška"),
        ("Closed manually by web console", "Uždaryta rankiniu būdu naudojant žiniatinklio konsolę"),
        ("Local keyboard type", "Vietinės klaviatūros tipas"),
        ("Select local keyboard type", "Pasirinkite vietinės klaviatūros tipą"),
        ("software_render_tip", "Jei turite Nvidia vaizdo plokštę ir nuotolinis langas iškart užsidaro prisijungus, gali padėti „Nouveau“ tvarkyklės įdiegimas ir programinės įrangos atvaizdavimo pasirinkimas. Būtina paleisti iš naujo."),
        ("Always use software rendering", "Visada naudoti programinį spartintuvą"),
        ("config_input", "Norėdami valdyti nuotolinį darbalaukį naudodami klaviatūrą, turite suteikti RustDesk leidimus \"Įvesties monitoringas\"."),
        ("config_microphone", "Norėdami kalbėtis su nuotoline puse, turite suteikti RustDesk leidimą \"Įrašyti garsą\"."),
        ("request_elevation_tip", "Taip pat galite prašyti tesių suteikimo, jeigu kas nors yra nuotolinėje pusėje."),
        ("Wait", "Laukti"),
        ("Elevation Error", "Teisių suteikimo klaida"),
        ("Ask the remote user for authentication", "Klauskite nuotolinio vartotojo autentifikavimo"),
        ("Choose this if the remote account is administrator", "Pasirinkite tai, jei nuotolinė paskyra yra administratorius"),
        ("Transmit the username and password of administrator", "Persiųsti administratoriaus vartotojo vardą ir slaptažodį"),
        ("still_click_uac_tip", "Vis tiek reikia, kad nuotolinis vartotojas paleidžiant RustDesk UAC lange paspaustų \"OK\"."),
        ("Request Elevation", "Prašyti teisių"),
        ("wait_accept_uac_tip", "Palaukite, kol nuotolinis vartotojas patvirtins UAC užklausą."),
        ("Elevate successfully", "Teisės suteiktos"),
        ("uppercase", "didžiosios raidės"),
        ("lowercase", "mažosios raidės"),
        ("digit", "skaitmuo"),
        ("special character", "specialusis simbolis"),
        ("length>=8", "ilgis>=8"),
        ("Weak", "Silpnas"),
        ("Medium", "Vidutinis"),
        ("Strong", "Stiprus"),
        ("Switch Sides", "Perjungti puses"),
        ("Please confirm if you want to share your desktop?", "Prašome patvirtinti, jeigu norite bendrinti darbalaukį?"),
        ("Display", "Ekranas"),
        ("Default View Style", "Numatytasis peržiūros stilius"),
        ("Default Scroll Style", "Numatytasis slinkties stilius"),
        ("Default Image Quality", "Numatytoji vaizdo kokybė"),
        ("Default Codec", "Numatytasis kodekas"),
        ("Bitrate", "Sparta"),
        ("FPS", "FPS"),
        ("Auto", "Automatinis"),
        ("Other Default Options", "Kitos numatytosios parinktys"),
        ("Voice call", "Balso skambutis"),
        ("Text chat", "Tekstinis pokalbis"),
        ("Stop voice call", "Sustabdyti balso skambutį"),
        ("relay_hint_tip", "Tiesioginis ryšys gali būti neįmanomas. Tokiu atveju galite pabandyti prisijungti per perdavimo serverį. \nArba, jei norite iš karto naudoti perdavimo serverį, prie ID galite pridėti priesagą \"/r\" arba nuotolinio pagrindinio kompiuterio nustatymuose įgalinti \"Visada prisijungti per relę\"."),
        ("Reconnect", "Prisijungti iš naujo"),
        ("Codec", "Kodekas"),
        ("Resolution", "Rezoliucija"),
        ("No transfers in progress", "Nevyksta jokių perdavimų"),
        ("Set one-time password length", "Nustatyti vienkartinio slaptažodžio ilgį"),
        ("idd_driver_tip", "Įdiekite virtualaus ekrano tvarkyklę (naudojama, kai nėra fizinių ekranų)"),
        ("confirm_idd_driver_tip", "Įjungta virtualaus ekrano tvarkyklės diegimo funkcija. Atminkite, kad bus įdiegtas bandomasis sertifikatas, kad būtų galima pasitikėti tvarkykle. Šis sertifikatas bus naudojamas tik pasitikėjimui Rustdesk tvarkyklėmis patikrinti."),
        ("RDP Settings", "RDP nustatymai"),
        ("Sort by", "Rūšiuoti pagal"),
        ("New Connection", "Naujas ryšys"),
        ("Restore", "Atkurti"),
        ("Minimize", "Sumažinti"),
        ("Maximize", "Padidinti"),
        ("Your Device", "Jūsų įrenginys"),
        ("empty_recent_tip", "Nėra paskutinių seansų!\nLaikas suplanuoti naują."),
        ("empty_favorite_tip", "Dar neturite parankinių nuotolinių seansų."),
        ("empty_lan_tip", "Nuotolinių mazgų nerasta."),
        ("empty_address_book_tip", "Adresų knygelėje nėra nuotolinių kompiuterių."),
        ("eg: admin", "pvz.: administratorius"),
        ("Empty Username", "Tuščias naudotojo vardas"),
        ("Empty Password", "Tuščias slaptažodis"),
        ("Me", "Aš"),
        ("identical_file_tip", "Failas yra identiškas nuotoliniame kompiuteryje esančiam failui."),
        ("show_monitors_tip", "Rodyti monitorius įrankių juostoje"),
        ("View Mode", "Peržiūros režimas"),
        ("login_linux_tip", "Norėdami įjungti X darbalaukio seansą, turite būti prisijungę prie nuotolinės Linux paskyros."),
        ("verify_rustdesk_password_tip", "Įveskite kliento RustDesk slaptažodį"),
        ("remember_account_tip", "Prisiminti šią paskyrą"),
        ("os_account_desk_tip", "Ši paskyra naudojama norint prisijungti prie nuotolinės OS ir įgalinti darbalaukio seansą režimu headless"),
        ("OS Account", "OS paskyra"),
        ("another_user_login_title_tip", "Kitas vartotojas jau yra prisijungęs"),
        ("another_user_login_text_tip", "Atjungti"),
        ("xorg_not_found_title_tip", "Xorg nerastas"),
        ("xorg_not_found_text_tip", "Prašom įdiegti Xorg"),
        ("no_desktop_title_tip", "Nėra pasiekiamų nuotolinių darbalaukių"),
        ("no_desktop_text_tip", "Prašom įdiegti GNOME Desktop"),
        ("No need to elevate", ""),
        ("System Sound", ""),
        ("Default", ""),
        ("New RDP", ""),
        ("Fingerprint", ""),
        ("Copy Fingerprint", ""),
        ("no fingerprints", ""),
        ("Select a peer", ""),
        ("Select peers", ""),
        ("Plugins", ""),
        ("Uninstall", ""),
        ("Update", ""),
        ("Enable", ""),
        ("Disable", ""),
        ("Options", ""),
        ("resolution_original_tip", ""),
        ("resolution_fit_local_tip", ""),
        ("resolution_custom_tip", ""),
    ].iter().cloned().collect();
}

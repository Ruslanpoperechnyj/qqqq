# :rocket: Statistics

In order to make statistics on a DC with more LDAP objects, run the [BadBlood](https://github.com/davidprowe/BadBlood) on the domain controller ESSOS.local from [GOAD](https://github.com/Orange-Cyberdefense/GOAD). The DC should now have around 3500 objects. Below is the average time it takes to run the following tools:

| Tool              | Environment         | Objects | Time     | Command      |
| -------------------------- | ----------------- | ---------- | -------  | -------  |
| SharpHound.exe        | Windows <img width="20px"  src="https://github.com/g0h4n/RustHound-CE/raw/main/img/windows.png"/> | ~3500   | ~51.605s | Measure-Command { sharphound.exe -d essos.local --ldapusername 'khal.drogo' --ldappassword 'horse' --domaincontroller '192.168.56.12' -c All } |
| BloodHound.py | Linux <img width="20px" src="https://github.com/g0h4n/RustHound-CE/raw/main/img/linux.png"/>    | ~3500   | ~9.657s  | time python3 bloodhound.py -u khal.drogo -p horse -d essos.local -ns 192.168.56.12 --zip -c all |
| RustHound.exe         | Windows <img width="20px"  src="https://github.com/g0h4n/RustHound-CE/raw/main/img/windows.png"/> | ~3500   | **~5.315s**  | Measure-Command { rusthound.exe -d essos.local -u khal.drogo@essos.local -p horse -z } | 
| RustHound         | Linux <img width="20px"  src="https://github.com/g0h4n/RustHound-CE/raw/main/img/linux.png"/>    | ~3500   | **~3.166s**  | time rusthound -d essos.local -u khal.drogo@essos.local -p horse -z  |

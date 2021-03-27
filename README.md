# exfinder

Very rudimentary PoC to search Windows's EVTX files like a SIEM.
## Requirements

- [evtx](https://github.com/omerbenamram/evtx)
- [jq](https://stedolan.github.io/jq/)

## Usage

First convert the EVTX dump to JSON

```powershell
./evtx_dump -o json Security.evtx > JsonLog.txt
```

Pre-process to convert it to pure JSON file

```sh
sed -E 's/Record [[:digit:]]+//g' JsonLog.txt > ProcJsonLog.txt
```

Start quering like a SIEM

```powershell
./exfinder.sh 'EventID=4688 Command=powershell.exe | project Host, User, Command'

./exfinder.sh 'EventID=4688 Command= -ma lsass'
```

## Note

- *project* has a definite hardcoded order and does not depend upon the order in the query.

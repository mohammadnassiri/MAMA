# MAMA
Multi Agent Malware Analyzer Framework. MAMA can control virtual machines and send malware to them for analyzing. After malware analyzed, its behavior logs and screenshots will sent to the server. This framework can be used to automating malware dynamic analysis was done by researchers manually. Each client as a virtual machine can run an agent. Agents do malware tracing and have communication protocol to the server. One of the agents, developed to use pintool and winapioverride, can be accessed from [MAMA-Agent](https://github.com/mohammadnassiri/MAMA-Agent).

## Install
The server has been written on Django framework and you can install it by this way:
```
git clone https://github.com/mohammadnassiri/MAMA.git
cd MAMA
pip3 install -r requirements.txt
python3 manage.py serve
```

## Config
Configuration can be made from ```.env ``` file.
First, generate new secret key:  
```
python3 -c "import string,random; uni=string.ascii_letters+string.digits+string.punctuation; print(repr(''.join([random.SystemRandom().choice(uni) for i in range(random.randint(45,50))])))"
```
Also .env file has below properties: 
- MACHINE_FILE_TIMEOUT: Virtual machine will revert after this time if script isn't responding (minutes).
- MACHINE_HW_TIMEOUT: Virtual machine will revert after this time if machine isn't responding (minutes).
- MACHINE_SLEEP_POWEROFF: Time to sleep after machine powered off (seconds).
- MACHINE_SLEEP_RESTORE: Time to sleep before restore from snapshot (seconds).
- MACHINE_RESTORE_RETRY_LIMIT: Limit of efforts to wakeup the machine.
- MACHIN_POWERON_WAIT: Time to sleep after machine powered on (seconds).

# Server
MAMA's server can:
- Send or receive samples and traced logs.
- Control virtual machines through VBoxManage.exe
- Add or remove virtual machines dynamically.
- Save results and states in the database.
- Check client's status periodically.

We will happy to listen issues and suggestions.

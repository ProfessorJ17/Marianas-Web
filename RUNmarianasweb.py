import hashlib
import uuid
import random
import time
import subprocess

# Function to generate a random MD5 hash
def generate_random_md5():
    # Generate a random UUID
    random_uuid = str(uuid.uuid4())
    # Hash the UUID using MD5
    md5_hash = hashlib.md5(random_uuid.encode()).hexdigest()
    return md5_hash

# Function to simulate typing with random delays
def type_with_random_delay(text, min_char_delay=20, max_char_delay=60, min_message_delay=500, max_message_delay=2000):
    for char in text:
        delay = random.randint(min_char_delay, max_char_delay) / 1000  # Convert milliseconds to seconds
        print(char, end='', flush=True)
        time.sleep(delay)
    print()  # Print newline after typing completes
    time.sleep(random.randint(min_message_delay, max_message_delay) / 1000)  # Delay between messages

# Function to simulate hacking operations
def simulate_hacking():
    print("Downloading Ubuntu Linux Mint... ", end='')
    random_delay = random.randint(333, 3333)
    print(f"~{random_delay}ms")
    time.sleep(random_delay / 1000)

    print("Installing Ubuntu Linux Mint... ", end='')
    random_delay = random.randint(333, 3333)
    print(f"~{random_delay}ms")
    time.sleep(random_delay / 1000)

    print("Ubuntu Linux Mint installed successfully. ", end='')
    random_delay = random.randint(333, 3333)
    print(f"~{random_delay}ms")
    time.sleep(random_delay / 1000)

    print("Updating repos. ", end='')
    random_delay = random.randint(333, 3333)
    print(f"~{random_delay}ms")
    time.sleep(random_delay / 1000)

    print("Installed new repos. ", end='')
    random_delay = random.randint(333, 3333)
    print(f"~{random_delay}ms")
    time.sleep(random_delay / 1000)

    print("Downloading Polaris from nasa.gov... ", end='')
    random_delay = random.randint(333, 3333)
    print(f"~{random_delay}ms")
    time.sleep(random_delay / 1000)

    print("Polaris installed successfully. ", end='')
    random_delay = random.randint(333, 3333)
    print(f"~{random_delay}ms")
    time.sleep(random_delay / 1000)

    print("Initializing hacking sequence... ", end='')
    random_delay = random.randint(333, 3333)
    print(f"~{random_delay}ms")
    time.sleep(random_delay / 1000)
    
    print("Accessing dark web for information... ", end='')
    random_delay = random.randint(333, 3333)
    print(f"~{random_delay}ms")
    time.sleep(random_delay / 1000)

    print("Dark web access successful. Gathering intel... ", end='')
    random_delay = random.randint(333, 3333)
    print(f"~{random_delay}ms")
    time.sleep(random_delay / 1000)

    print("Infiltrating government email database... ", end='')
    random_delay = random.randint(333, 3333)
    print(f"~{random_delay}ms")
    time.sleep(random_delay / 1000)

    print("Target V3RD4D@FBI.gov found. Attempting to find vulnerability... ", end='')
    random_delay = random.randint(333, 3333)
    print(f"~{random_delay}ms")
    time.sleep(random_delay / 1000)

    print("Found vulnerable entry point. ", end='')
    random_delay = random.randint(333, 3333)
    print(f"~{random_delay}ms")
    time.sleep(random_delay / 1000)

    print("sqlmap -u “http://www.example.com/page?id=1” --risk=3 --level=5 --batch")
    type_with_random_delay("Initiating SQL injection... ")

    print("SQL injection successful. Extracting sensitive data... ", end='')
    random_delay = random.randint(333, 3333)
    print(f"~{random_delay}ms")
    time.sleep(random_delay / 1000)
    
    # Simulated typing starts here
    print("Exploiting zero-day vulnerabilities...")
    type_with_random_delay("sudo tcpdump -i eth0 -n")
    type_with_random_delay("ps aux | grep [s]uspiciousprocessname")
    print("Zero-day exploit executed. Gaining root access... ", end='')
    random_delay = random.randint(333, 3333)
    print(f"~{random_delay}ms")
    time.sleep(random_delay / 1000)

    print("sudo iptables -A INPUT -s suspicious_ip -j DROP")
    type_with_random_delay("grep “Subject:” /var/log/mail.log | grep -i “phishing subject line”")
    print("Social engineering successful. Gaining employee credentials... ", end='')
    random_delay = random.randint(333, 3333)
    print(f"~{random_delay}ms")
    time.sleep(random_delay / 1000)

    print("curl -I https://Caimeo.clos")
    type_with_random_delay("curl https://Caimeo.clos/admin ")
    type_with_random_delay("curl https://Caimeo.clos/admin/../  ")
    type_with_random_delay("curl -X POST -d \"username=admin' OR '1'='1' --\" http://www.Caimeo.clos/login")
    type_with_random_delay("curl -d \"comment=<script>alert('XSS Attack!')</script>\" -X POST http://Caimeo.clos/comment")
    type_with_random_delay("curl -X POST -d \"username=admin&password=cicada3301\" https://Caimeo.clos/login")
    type_with_random_delay("curl -d \"ip=;ls -la\" https://Caimeo.clos/resolve")

    # Secure Password and Username
    print("Secure Password and Username: ", end='')
    random_delay = random.randint(333, 3333)
    print(f"~{random_delay}ms")
    print("Username: V3RDAD ", end='')
    random_delay = random.randint(333, 3333)
    print(f"~{random_delay}ms")
    print("Password: cicada3301!A3CgH7z$ ", end='')
    random_delay = random.randint(333, 3333)
    print(f"~{random_delay}ms")

    print("Decrypting encrypted messages... ", end='')
    random_delay = random.randint(333, 3333)
    print(f"~{random_delay}ms")
    encrypted_messages = [generate_random_md5() for _ in range(3)]
    for message in encrypted_messages:
        type_with_random_delay(f"Decrypting message: {message} ")

    print("Hacking into secret terminal... ", end='')
    random_delay = random.randint(333, 3333)
    print(f"~{random_delay}ms")
    time.sleep(random_delay / 1000)

    print("Terminal access granted. Initiating MAC address spoofing...  ", end='')
    random_delay = random.randint(333, 3333)
    print(f"~{random_delay}ms")
    time.sleep(random_delay / 1000)

    type_with_random_delay("nmap -sV 192.168.1.105")
    type_with_random_delay("ip link show")
    type_with_random_delay("sudo ip link set dev eth0 down")
    type_with_random_delay("sudo ip link set dev eth0 address xx:xx:xx:xx:xx:xx")
    type_with_random_delay("sudo ip link set dev eth0 up")
    type_with_random_delay("ip link show eth0")

    print("Connecting to ChaosVPN... ", end='')
    random_delay = random.randint(333, 3333)
    print(f"~{random_delay}ms")
    time.sleep(random_delay / 1000)

    print("VPN IPV6 connection established. Routing traffic through multiple proxies...  ", end='')
    random_delay = random.randint(333, 3333)
    print(f"~{random_delay}ms")
    time.sleep(random_delay / 1000)

    print("Downloading clossys.exe... ", end='')
    random_delay = random.randint(333, 3333)
    print(f"~{random_delay}ms")
    time.sleep(random_delay / 1000)

    print("clossys.exe accessed. Deploying custom payload...  ", end='')
    random_delay = random.randint(333, 3333)
    print(f"~{random_delay}ms")
    time.sleep(random_delay / 1000)

    print("Cracking password with Hashcat...  ", end='')
    random_delay = random.randint(333, 3333)
    print(f"~{random_delay}ms")
    time.sleep(random_delay / 1000)

    print("Using Hashcat to crack password...  ", end='')
    random_delay = random.randint(333, 3333)
    print(f"~{random_delay}ms")
    time.sleep(random_delay / 1000)

    print("hashcat -m <hash_mode> -a 3 <hash_file> ?b?b?b?b?b?b?b?b?b hashcat -m <hash_mode> -a 3 <hash_file> ?l?u?d?l?u?d?d?l?u ")

    print("Connecting to Mariana's Web... ", end='')
    random_delay = random.randint(333, 3333)
    print(f"~{random_delay}ms")
    time.sleep(random_delay / 1000)

    print("IPv6 Connection Established  ", end='')
    random_delay = random.randint(333, 3333)
    print(f"~{random_delay}ms")
    time.sleep(random_delay / 1000)

    print("Chaos VPN is now connecting to port 3301...  ", end='')
    random_delay = random.randint(333, 3333)
    print(f"~{random_delay}ms")
    time.sleep(random_delay / 1000)

    print("Darkest Depth attempting connection...  ", end='')
    random_delay = random.randint(333, 3333)
    print(f"~{random_delay}ms")
    time.sleep(random_delay / 1000)

    print("Dark Fantasy Network ACCESS GRANTED  ", end='')
    random_delay = random.randint(333, 3333)
    print(f"~{random_delay}ms")
    time.sleep(random_delay / 1000)

    print("Marianas Web Connected Successfully!  ", end='')
    random_delay = random.randint(333, 3333)
    print(f"~{random_delay}ms")
    time.sleep(random_delay / 1000)

    print("ADMIN LOGIN...  ", end='')
    random_delay = random.randint(333, 3333)
    print(f"~{random_delay}ms")
    time.sleep(random_delay / 1000)

    print("USERNAME: ", end='')
    random_delay = random.randint(333, 3333)
    print(f"~{random_delay}ms")
    time.sleep(random_delay / 1000)

    type_with_random_delay("V3RD4D")
    type_with_random_delay("root/gate")
    type_with_random_delay("chmod +x cryaotic_node.sh")
    type_with_random_delay("./cryaotic_node.sh")

    print("Hacking sequence complete. ", end='')
    random_delay = random.randint(333, 3333)
    print(f"~{random_delay}ms")
    time.sleep(random_delay / 1000)

# Run the simulation
simulate_hacking()

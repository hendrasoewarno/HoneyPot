# HoneyPot
Salah satu upaya untuk meningkatkan keamanan server adalah memasang HoneyPot untuk mengalihkan perhatian penyerang, sehingga pada saat yang bersamaan network administrator memiliki waktu untuk mempelajari teknik penyerangan dan menilai resiko dan melakukan mitigasi pada konfigurasi server yang ada.

# Instalasi

# Instalasi MongoDB
```
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/4.4 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-4.4.list
sudo apt-get update
sudo apt-get install -y mongodb-org
systemctl start mongod
systemctl enable mongod
```
# Instalasi Docker
```
sudo apt install docker.io
systemctl start docker
systemctl enable docker
```

# Instalasi OWASP HoneyPot
```
cd /home/kali
apt-get update
sudo apt install libpcap-dev libnet-dev tshark
git clone https://github.com/zdresearch/OWASP-Honeypot.git
cd OWASP-Honeypot
pip install -r requirements.txt
```

# Konfigurasi HoneyPot
```
cd /home/kali/OWASP-Honeypot
pico config.py
def user_configuration():
    """
        user configuration

    Returns:
        JSON/Dict user configuration
    """
    return {
        "language": "en",
        "events_log_file": "tmp/ohp.log",
        "default_selected_modules": "all",  # or select one or multiple (e.g. ftp/strong_password,ssh/strong_password)
        "default_excluded_modules": "ftp/strong_password,ssh/strong_password,smtp/strong_password,http/basic_auth_strong_password"  # or any module name separated with comma
    }
```

# Menjalankan HoneyPot
Menjalankan module HoneyPot dengan konfigurasi default
```
python3 ohp.py
```
Menjalankan module API Server untuk menyediakan interface melalui browser yang dapat diakses pada 127.0.0.1:5000.
```
python3 ohp.py --start-api-server
```

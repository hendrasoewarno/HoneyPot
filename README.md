# HoneyPot
Salah satu upaya untuk meningkatkan keamanan server adalah memasang HoneyPot untuk mengalihkan perhatian penyerang, sehingga pada saat yang bersamaan network administrator memiliki waktu untuk mempelajari teknik penyerangan dan menilai resiko dan melakukan mitigasi pada konfigurasi server yang ada.

# Instalasi

# Instalasi Kali Linux
```
https://www.offensive-security.com/kali-linux-arm-images/
```
# Instalasi Database
OWASP HoneyPot menggunakan database mongodb
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
sudo apt install libpcap-dev libnet-dev tshark #wireshark
git clone https://github.com/zdresearch/OWASP-Honeypot.git
cd OWASP-Honeypot
pip install -r requirements.txt
```

# Konfigurasi Module HoneyPot
Menggunakan database mangodb lokal:
```
apt-get install docker-compose
docker-compose up #untuk membangun kembali image database yang terbaru
```
Untuk menentukan module apa saja yang ingin diaktifkan:
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

Jenis-jenis module yang ada:
1. SSH
2. FTP
3. HTTP
4. ICS
5. SMTP

Masing-masing module terdiri dari weak_password dan strong_password, dimana weak_password lebih ditujukan kepada aktifitas yang dilakukan penyerang setelah berhasil login dengan password, misalkan user:root password:123456, sedangkan strong_password ditujukan untuk memantau credential atas user dicoba dan password yang digunakan oleh penyerang untuk masuk ke system (misalkan penyerang berhasil mendapatkan user account, dan mencoba melakukan brute force atas password account tersebut, atau misalkan user telah mendapatkan user dan password melalui upaya sosial engineering) sehingga kita dapat mengetahui user dan password yang kompromis.

# Menjalankan HoneyPot
Menjalankan module HoneyPot dengan konfigurasi default
```
python3 ohp.py
```
Menjalankan section API Server untuk menyediakan WebUI + API melalui browser yang dapat diakses pada 127.0.0.1:5000.
```
python3 ohp.py --start-api-server
```

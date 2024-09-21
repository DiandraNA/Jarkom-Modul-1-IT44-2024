# Jarkom-Modul-1-IT44-2024
| Nama                     | NRP         |
| -------------------------| ----------- |
| Diandra Naufal Abror     | 5027231004  |
| Acintya Edria Sudarsono  | 5027231020  |

Write Up Modul 1.
- [Advance Sanity Check](#advance-sanity-check)
- [Corporate Breach](#corporate-breach)
- [Surprise](#surprise)
- [Gajah Terbang (server recon)](#gajah-terbang-server-recon)
- [Pegawai Negeri Sebelah](#pegawai-negeri-sebelah)
- [EZ](#ez)
- [FTP Login](#ftp-login)
- [Illegal Breakthrough](#illegal-breakthrough)
<br />

**REVISI**

## Advance Sanity Check
pada clue diberikan ip address nc 10.15.42.60 44000. Jika dijalankan, tampilannya seperti ini : <br />
![image](https://github.com/user-attachments/assets/2b1be634-62a3-43d5-8b77-2609ffc9b445)<br />
Pada packet 44 terdapat info login pada http/1.1 Jika difollow streamnya maka muncul seperti ini
![image](https://github.com/user-attachments/assets/6794a7b6-f95e-453f-874d-6236f9a1502a)<br />
dan pada stream 3 terdapat username pengirim <br />
![image](https://github.com/user-attachments/assets/4dc2b78c-4523-4967-8fea-eeab11b26a59)<br />
Jika diinput kembali pada 10.15.42.60 44000 maka akan diterima sebagai jawaban benar. Dan selanjutnya perlu untuk mencari nama file yang dikirim. Pada packet 79 dengan header POST /upload.php terdapat clue
![image](https://github.com/user-attachments/assets/4671f613-fea9-4bdf-8d23-1d086ed20b4d)<br /> Clue yang didapat adalah cGVud29yZA== jike di encode menggunakan base64 maka akan didapat "penword"<br />
![image](https://github.com/user-attachments/assets/81005f77-317e-4e16-a5a5-33cce59c581a)

### FLAG
`JarkomIT{8uK4n_S4n1ty_b1a5A_41pctZxGk6SeQyyvrznzm0LLuSu5V5GdC7fAfZoVK1zJXlfXm6JnPIKK}`

-----------------------------------------------------------------------------------------------

## CORPORATE BREACH
nc 10.15.42.60 51000 <br />
pada packet no 23 terdapat clue "Who has 172.21.80.1? Tell 172.21.88.207" Jika kita apply filter untuk conversation antara 172.21.88.207 dan 172.21.80.1 maka akan ditemukan nama hacker pada packet no. 4 dengan header POST <br />
![image](https://github.com/user-attachments/assets/75dcde4e-7ba8-42d0-aaec-30149acc327e) <br />
Lalu selanjutnya perlu dicari email yang digunakan untuk login. Dari packet dapat dilihat bahwa hacker melakukan brute forcing dengan banyak email. Pertama filter untuk melihat semua traffic post login _http.request.method == "POST"_. Terdapat satu packet dengan length yang lebih besar daripada packet lainnya. <br />
![image](https://github.com/user-attachments/assets/5bef3b60-104a-4793-838a-e96b5a9ee454) <br />
![image](https://github.com/user-attachments/assets/a8082190-8dda-45a7-9b68-7a13f157a5f0) <br />

### FLAG
JarkomIT{supp0rt_k0k_l3m4h_bg_rzWkD6HFKCvIH957HVqpZmYKPG6vTFmncEv5DJ8Ti2PZnOI0J7QfG6}

-----------------------------------------------------------------------------------------------
## Surprise
nc 10.15.42.60 48500 <br />
Pada header packet 12 berjudul response 220 vsFTPd 3.0.3. Command untuk mengirim file adalah STOR maka kita dapat apply filter untuk mencari traffic yang mengirim file _frame contains "STOR"_ <br />
![image](https://github.com/user-attachments/assets/357d6773-9a62-4ee4-bdd6-4daddb862a06) <br />
Lalu jika di follow streamnya maka akan ditemukan content dari g0tcha.cpp
```
#include <iostream>
#include <string>
#include <vector>
using namespace std;

string generateString() {
    auto tochip = [](int num) -> string {
        string chipStr;
        if (num < 0 || num > 255) return "";
        char buffer[3];
        snprintf(buffer, sizeof(buffer), "%02x", num);
        chipStr = buffer;
        return chipStr;
    };

    vector<int> chipParts = {103, 48, 116, 99, 104, 117, 32, 110, 48, 119, 32, 108, 49, 116, 116, 108, 51, 32, 109, 48, 117, 115, 51};

    string result;
    for (int part : chipParts) {
        result += static_cast<char>(part);
    }

    return result;
}

int main() {
    string result = generateString();

    cout << result << endl;

    return 0;
}
```
Jika dijalankan maka outputnya _g0tchu n0w l1ttl3 m0us3_
### FLAG
JarkomIT{l1ttl3_m0us3_1n_th3_h0us3_2m7YEkpb2B82nVnWVAvP1Oi3uG0yLK34UQMQQJOFEvlg79Rr26wgTCHU}

-----------------------------------------------------------------------------------------------

## GAJAH TERBANG (Server recon)
Terdapat banyak packet yang menggunakan PGSQL protocol yang mengindikasikan bahwa PostgreSQL digunakan. ketika TCP handshake berlangsung dilihat bahwa syn packet menuju port 6969 sehingga server dbms berjalan pada port 6969.
Pada packet no 164 dapat dilihat bahwa os yang digunakan adalah Debian 16.4-1 <br />
![image](https://github.com/user-attachments/assets/e457667e-be35-4dc0-ad20-843a85a2fbf9) <br />
Pada packet ini juga dapat dipastikan bahwa username valid adalah _s1gm4_ dan nama database _sigmaskibidigyatrizzzz_. Dapat dilihat bahwa jojohermawan@gmail.com memiliki role admin dan untuk passwordnya dapat dilakukan dekripsi hash MD5 yang menghasilkan _admin1234_


### FLAG
JarkomIT{Gy4tT_M5g_4U_7iZK7YAU30kGtJaDWlvGCFgPG5k1IKFtHNko8oNfaJkxWFib15tkiBiD1}

-----------------------------------------------------------------------------------------------

## Pegawai Negeri Sebelah
Terdapat _challange_ dengan keterangan sebagai berikut, "Kamu seorang data analisis diminta untuk memastikan ulang data-data dari beberapa pegawai.". Berikut adalah alur pengerjaan saya:
- Siapa yang memiliki password nNnM%coQuF?
  Langkah pertama adalah membuka **rahasia.pcap** di Wireshark, lalu menjalankan filter `frame contains "nNnM%coQuF"` untuk mencari individu yang memiliki password spesifik tersebut. Setelah mendapat paket, saya mengikuti TCP Stream dan mencari kata kunci tersebut. Dan muncul "Vero Tampubolon".
  ![image](https://github.com/user-attachments/assets/4e83249a-4d1e-4fd7-845d-710ec7b2856d)
- Apa jabatan dari Taufan Kuswandari?
  Masih dengan paket yang sama, saya mencari nama tersebut dan mendapatkan hasil "Analis Kebijakan".
  ![Kali Linux 2024 3 (Debian 12 x) 64-bit - VMware Workstation 18_09_2024 23_27_48](https://github.com/user-attachments/assets/636fac9e-7a7e-40f0-b540-350ec5299fa4)
- Siapa yang paling awal di list?
Dengan teknik yang sama, saya menemukan "Cici Mustofa" dengan mencari data pertama.
![Kali Linux 2024 3 (Debian 12 x) 64-bit - VMware Workstation 18_09_2024 23_27_48](https://github.com/user-attachments/assets/e1c4b04c-5922-4e5e-9cbc-ef80e07d6195)
- Apa password paling akhir dari list?
Hasilnya adalah "RyxaJPv^yF".
![Kali Linux 2024 3 (Debian 12 x) 64-bit - VMware Workstation 18_09_2024 23_30_46](https://github.com/user-attachments/assets/3729a8c8-836f-4ecd-bc62-81e476880af1)
### Benar! Ini flag-mu: `JarkomIT{Tum8eN_p45SnYa_Ku4t_B1aS4Nya_ba95q8Auofp6UEJe9rcN4i07aL3kbeGnqOFMqVukmKZaLYahyw7EM4h}`

## EZ
Terdapat _challange_ dengan keterangan sebagai berikut, "Aku sedang mencoba bikin chat service tapi kayanya pesannya bisa di sniffing deh? coba temukan pesannya.". Berikut adalah alur pengerjaan saya:
- Temukan jawaban dari log tersebut
  Setelah membuka **ez.pcap**. Saya lalu membuka paket pertama dan mengikuti TCP Streamnya, lalu _scroll_ hingga menemukan sebuah jawaban yaitu "jawabannya jawaban".
  ![Kali Linux 2024 3 (Debian 12 x) 64-bit - VMware Workstation 18_09_2024 23_36_23](https://github.com/user-attachments/assets/e179aefa-8dab-4b06-8a62-48ff109ef35d)
- Port berapa yang digunakan service tersebut
Saya cek _port_ paket tersebut.
  ![Kali Linux 2024 3 (Debian 12 x) 64-bit - VMware Workstation 18_09_2024 23_39_08](https://github.com/user-attachments/assets/2fdeb593-07be-4275-b634-8d28b0ec6514)
### Benar! Ini flag-mu: `JarkomIT{BiAr_aman_Pake_sSh_NyIIib1a7K632z7rgX3agwGU93zdMHl5HoXo3IRXYSycbWLrZzu9EZ}`

## FTP Login
Terdapat _challange_ dengan keterangan sebagai berikut, "Seseorang menemukan sebuah celah dalam sebuah server. Ia mencoba untuk melakukan brute force login dan ia berhasil masuk. Lakukan pemeriksaan untuk melihat apa yang dilakukan oleh orang tersebut!". Berikut adalah alur pengerjaan saya:
- Apa username yang berhasil digunakan untuk FTP login?
**ftplogin.pcapng** berhasil dibuka, saya gunakan _feeling_ dengan membuka FTP yang berada di akhir paket. Dan muncul keterangan "Login successful", saya buka paket tersebut dan mengikuti TCP Streamnya. Terdapat keterangan bahwa pengguna "sn34ky" berhasil _login_ dengan _password_ "sup3rsn1ff3r".
![Kali Linux 2024 3 (Debian 12 x) 64-bit - VMware Workstation 18_09_2024 23_49_58](https://github.com/user-attachments/assets/439dda90-5f5b-42a0-8dfa-d3fbc92dadf1)
- Apa password yang berhasil digunakan untuk FTP login?
  Tentu saja "sup3rsn1ff3r".
### Benar! Ini flag-mu: `JarkomIT{n0t_s0_s3cur3_ftp_O85JzJ2SJhrZjhC0G9UheO56nL03L4jugvymlYiwogfwbgUJ79OtG1N}`

## Illegal Breakthrough
Terdapat _challange_ dengan keterangan sebagai berikut, "Seorang full-stack developer bernama kevin sedang membuat sebuah web yang memiliki login page. Tetapi karena ia hanya digaji rendah, ia lupa untuk mengamankan web yang ia buat. Bantulah kevin untuk tracing dari jejak yang ditinggalkan oleh attacker.". Berikut adalah alur pengerjaan saya:
- Apa IP address dari korban?
Setelah melihat **break.pcapng**, paket pertama memiliki _destination_ "172.21.88.207".
![Kali Linux 2024 3 (Debian 12 x) 64-bit - VMware Workstation 18_09_2024 23_54_27](https://github.com/user-attachments/assets/29bd3646-ef42-4306-80d0-acd1941c629d)
- Apa port yang digunakan sebagai webserver?
  Tentu saja "1917", kita dapat melihatnya dari informasi paket.
- Dimana endpoint yang terdapat login?
  Di "/ww1.php", kita bisa melihatnya dari informasi paket.
- Tools apa yang digunakan oleh attacker?
  Saya buka salah satu paket dengan protokol HTTP, saya mendapatkan hasil "Fuzz Faster U Fool v2.1.0-dev" setelah mengikuti TCP Streamnya. Namun jawaban yang diinginkan adalah "ffuf-v2.1.0-dev".
![Kali Linux 2024 3 (Debian 12 x) 64-bit - VMware Workstation 18_09_2024 23_58_44](https://github.com/user-attachments/assets/522829fe-efce-4639-87e8-57ee3fc10db1)
- Apa kredensial yang berhasil digunakan oleh attacker untuk login?
  Berhubung saya sudah mengetahui identitas _attacker_ yaitu "Redbarron", saya menggunakan `frame contains "Redbaron" lalu memilih paket terakhir dengan asumsi bahwa ia sudah berhasil login. Dan memang ia berhasil login dengan _password_ "fly1ng4c3". Maka jawaban yang diinginkan adalah "Redbaron:fly1ng4c3"
![Kali Linux 2024 3 (Debian 12 x) 64-bit - VMware Workstation 19_09_2024 00_05_29](https://github.com/user-attachments/assets/724a19ba-a530-4b3a-bb1d-df36b9cf1b62)
### Benar! Ini flag-mu: `JarkomIT{d34th_fr0m_th3_sky_JQLrqB7mInNbSyRFyEYoQRCeZH1XEzy3Hnsk4hykmNp7IWWwoI4zWW1}`

--------------------------------------------------------------------------------------------------------
# REVISI
## Packets Barrage
nc 10.15.42.60 47000 <br />
Dapat dilihat dari traffic bahwa ip penyerang adalah _172.21.80.1_ <br />
![Screenshot 2024-09-21 103115](https://github.com/user-attachments/assets/cb0cce70-51c9-41b5-b723-1f3523643927) <br />
Dengan memfilter _http.request.method == "POST"_ didapat 1918 packet tapi karena un/pw di tcp.stream eq 1917 sudah ditemukan maka total attempt 1917. <br />
Selanjutnya untuk mencari file yang di download attacker <br />
![image](https://github.com/user-attachments/assets/f59e71cc-f05a-431b-8a28-974ffe3eca6d) <br />
Dari packet 19249 dapat dipastikan bahwa nama file yang di download _Albatros.txt_ dan isinya _Der Rote Kampfflieger_

### FLAG
JarkomIT{th3_fly1ng_c1rcus_0f_w4r_rSSczHdZYSXlh9gWiy7ZWAq8R5St8AckPqhRlmOaTw353Zm7Sg3oLACE}



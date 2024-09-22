![Kali Linux 2024 3 (Debian 12 x) 64-bit - VMware Workstation 22_09_2024 18_17_01](https://github.com/user-attachments/assets/c809e7f2-87fd-497e-982c-5d23147a6129)# Jarkom-Modul-1-IT44-2024
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
- [Packets Barrage](#packets-barrage)
- [Malicious Code](#malicious-code)
- [Rizzset](#rizzset)
- [Gajah Terbang (attacker recon)](#gajah-terbang-attacker-recon)
- [22 Nightmare](#22-nightmare)
- [InnerRCE](#innerrce)
- [Baby Hengker](#baby-hengker)
- [Adult Hengker](#adult-hengker)
- [Stegography](#stegography)

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
`JarkomIT{supp0rt_k0k_l3m4h_bg_rzWkD6HFKCvIH957HVqpZmYKPG6vTFmncEv5DJ8Ti2PZnOI0J7QfG6}`

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
`JarkomIT{l1ttl3_m0us3_1n_th3_h0us3_2m7YEkpb2B82nVnWVAvP1Oi3uG0yLK34UQMQQJOFEvlg79Rr26wgTCHU}`

-----------------------------------------------------------------------------------------------

## GAJAH TERBANG (Server recon)
Terdapat banyak packet yang menggunakan PGSQL protocol yang mengindikasikan bahwa PostgreSQL digunakan. ketika TCP handshake berlangsung dilihat bahwa syn packet menuju port 6969 sehingga server dbms berjalan pada port 6969.
Pada packet no 164 dapat dilihat bahwa os yang digunakan adalah Debian 16.4-1 <br />
![image](https://github.com/user-attachments/assets/e457667e-be35-4dc0-ad20-843a85a2fbf9) <br />
Pada packet ini juga dapat dipastikan bahwa username valid adalah _s1gm4_ dan nama database _sigmaskibidigyatrizzzz_. Dapat dilihat bahwa jojohermawan@gmail.com memiliki role admin dan untuk passwordnya dapat dilakukan dekripsi hash MD5 yang menghasilkan _admin1234_


### FLAG
`JarkomIT{Gy4tT_M5g_4U_7iZK7YAU30kGtJaDWlvGCFgPG5k1IKFtHNko8oNfaJkxWFib15tkiBiD1}`

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
`JarkomIT{th3_fly1ng_c1rcus_0f_w4r_rSSczHdZYSXlh9gWiy7ZWAq8R5St8AckPqhRlmOaTw353Zm7Sg3oLACE}`

------------------------------------------------------------------------------------------------------------------
## Malicious Code
File sama seperti corporate breach <br />
Untuk mencari tahu berapa kali attacker melakukan listing dapat menggunakan filter _http.request.method == "GET"_.
Dapat dilihat attacker melakukan bruteforcing beberapa kali sebelum akhirnya mendapatkan endpoint untuk login page _/index.php_ <br />
![image](https://github.com/user-attachments/assets/564ae96d-3a90-4d70-9424-0aeec824cfff) <br />
Attacker berhasil mendapatkan email dan password yang benar pada attempt ke _153_ <br />
![image](https://github.com/user-attachments/assets/cb969a5b-c9bd-478b-b422-033ddc7e3d6c) <br />
Pada stream 221 didapat pesan terenkripsi dari attacker `9711297321199711411097321029711811111410511632112101109981179711632991049710810810111010310163324010410511011658321151191019711610111441`
Jikaa di decode menggunakan ascii translator maka akan didapat pertanyaan dari attacker. <br />
![image](https://github.com/user-attachments/assets/cb5776af-ae98-4426-8057-db3765ec33aa) <br />
jawabannya `merah` _di bruteforce aja cobain semua_


### FLAG
`JarkomIT{s3cr3t_m3ss4ge_fr0m_4uth0r_VGszlHQVO2ASDMSpItu7bAgXKC0FdPBgkxRg6w4Ev6Hj1wp8cjnCL0R}`

------------------------------------------------------------------------------------------------------------------
## Rizzset
Ketika packet dibuka langsung terlihat nama domain <br />
![image](https://github.com/user-attachments/assets/8a575af3-2434-4c23-bd2f-31654381d9a4) <br />
Pada packet terdapat clue _Who has 172.24.128.1? Tell 172.24.141.242_ maka saya apply filter untuk conversation antara keduanya. dan jika difollow stream maka akan ketemu ip address <br />
![image](https://github.com/user-attachments/assets/32bdd6af-ed2e-4773-887e-e5c12742c51b) <br />
`103.94.189.5` <br />
apa JARM fingerprintnya?
![image](https://github.com/user-attachments/assets/53ee6e58-fac1-4b4f-99cd-235251c8729a)
`2ad2ad16d2ad2ad22c2ad2ad2ad2ad74aaecca9f9c4a3303863dfee62b241e`


### FLAG
`JarkomIT{Dn5_C0rR34t10n_mWHKnQ1WRkOrfhA1oHghjvTgwr1zZEkVtVfDnwMIIffX8z4wmlsflh1T5}`

----------------------------------------------------------------------------------------------------------------------
## Gajah Terbang (Attacker Recon)
Untuk mencari tahu siapa attackernya, saya kembali mengecek daftar database user. Karena ada satu user yang letaknya tidak berurut sesuai dengan id-nya maka saya coba dan ternyata benar. <br />
![image](https://github.com/user-attachments/assets/abbd17ba-9679-43fa-b0b8-099fd503a4b7) <br />
`kuntoajiisrillll@gmail.com` <br />
Lalu tinggal decode passwordnya menggunakan hash md5 _aa1cbddbb1667f7227bcfdb25772f85c_ jadi `kissme` <br />
Informasi mengenai kapan user tersebut di-ban juga dapat dilihat dari packet <br />
![image](https://github.com/user-attachments/assets/390e8447-adce-4e45-a6ea-bbaa5fe9f26b)<br />
`2024-06-09` <br />
Lalu dari informasi tersebut juga dapat ditarik kesimpulan bahwa tabel yang dimodifikasi attacker adalah tabel user (posisi data user tidak berurut) dan banned user. <br />
![image](https://github.com/user-attachments/assets/ead90b43-bca0-4f68-b840-d0030d00f8f2) <br />
Barang yang telah dibeli attacker adalah `rokok dan es krim`. Totalnya 18000 + 6500 = `24500`

### FLAG
`JarkomIT{G4jaH_K0k_t3RbaNG_gfMgXdBz23qI8NfNWZMMC4mYEYntKKGQ1KhECjHfh2amANyvFL6HKKt5}`

----------------------------------------------------------------------------------------------------------------------------
## 22 Nightmare
Terdapat clue pada packet ![image](https://github.com/user-attachments/assets/765abf58-4736-4851-b1c3-ffbb3a31f16e) <br />
Jika kita filter conversation antara keduanya dapat diilihat bahwa attacker mencoba melakukan login beberapa kali sebelum berhasil.
Untuk mengetahui file yang dikirim penyerang kita dapat coba menggunakan filter _frame contains "STOR"_ <br />
![image](https://github.com/user-attachments/assets/4ad10212-e20a-4322-8d1d-f6cbbf93b0fc) <br />
Selanjutnya export object - ftp data untuk mendapatkan file sh1k4.jpg dan st0r.py <br />
![image](https://github.com/user-attachments/assets/dcb8a67e-9b58-4a47-a30d-1dc1a7b3916f) <br />
Lalu dalam file St0r.py terdapat kode biner `001001100011010000100010001000100011101001101110001001110011100001101110000110100011101000111100001011110011111000100001011011100001111000100001001111010011110100100111`
 jika di decode `hallo im Torako Koshi`

### FLAG
`JarkomIT{Sh1k4n0ko_N0_k05h1tan_5GtovoFqcG0nnXDHTguLEpsGJ7AnbPKu8xNFqp8SCeehCotWUQYLmUNU}`

-----------------------------------------------------------------------------------------------------------------------------`

## InnerRCE
Jika kita apply filter `frame contains "POST"` maka akan tersisa 2 packet dan salah satunya berhasil upload <br />
![image](https://github.com/user-attachments/assets/1d613851-84d5-4505-b241-4e1a2ac67a44) <br />
maka waktunya adalah `2024-09-16 13:18:05` <br />
![image](https://github.com/user-attachments/assets/8a13f8f1-ef33-4091-a87b-8d4c764a6a63) <br />
Maka pathnya adalah `/upload.php_server-app`
![image](https://github.com/user-attachments/assets/d5accfa6-7560-4cd7-858c-837816b712c2) <br />
pada stream 27 dapat dilihat hacker berhasil upload webshell `idzoyyshell.php` <br />
![image](https://github.com/user-attachments/assets/c01142e3-ca4a-4131-b1ba-3ed137781dd6) <br />
Dapat dilihat bahwa command pertama yang dijalankan adalah `whoami`. Jika stream terus di follow maka kita akan temukan pesan yang hacker tuliskan. <br />
![image](https://github.com/user-attachments/assets/05e2f2c6-fdb6-4a7d-9580-a3b026d5a896) <br />
Jika di decode menggunakan base64 `pls rate soal ini`



### FLAG
`JarkomIT{P4L1nG_g4mPaNg_An4L1sA_W3b_aTk_rXmiHvtHy7LKQVZBtLTFecXJtW4iGUAin4zKblP6f29dXpYXCUy9bRCE}`

## Baby Hengker
Terdapat _challange_ dengan keterangan sebagai berikut, "Pada suatu hari, ada seorang mahasiswa yang menyusup kedalam lab. mahasiswa tersebut menyalakan salah satu komputer yang ada dan mulai mengetikkan sesuatu?!?!?! bantulah mas aji menganalisa apa yang dilakukan oleh mahasiswa tersebut.". Berikut adalah alur pengerjaan saya:
- Kapan hacker tersebut mengakses komputer yang ada di lab?
  Saya membuka **innerchild.pcap**, lalu membuka peket dengan detail "URB_INTERRUPT in". Mengindikasikan sebuah _device_ baru saja terhubung pada 2024-09-16 13:43.
![Kali Linux 2024 3 (Debian 12 x) 64-bit - VMware Workstation 22_09_2024 18_17_01](https://github.com/user-attachments/assets/5dd21bd7-2ad8-4bfb-9d1d-cf4229ba82ff)
- Apa yang dituliskan oleh hacker tersebut?
  Berhubung file .pcap tersebut berulangkali menunjukkan HID Data, saya menggunakan _script_ untuk mengkonversi data tersebut ke dalam karakter alfabet. Hasil yang didapatkan adalah "ini ppassword wiffinyya appa ya?". Setelah mengurangi karakter yang repetitif dan melakukan _bruteforce_. Saya menemukan kata kunci "ini passwordnya apa ya?".
### Benar! Ini flag-mu: `JarkomIT{4ku_p9n_j4d1_h3n9k3r_Y0cfeXATCLjIcMIAUdhKnvkXDAm1w103I8uvbweUVkHM7sC6M07BSHCK}`

## Adult Hengker
Terdapat _challange_ dengan keterangan sebagai berikut, "Setelah sang mahasiswa tau passwordnya, dia akhirnya bisa masuk ke komputer dan menuliskan sesuatu di ms paint, apakah kamu tau dia menulis apa?". Berikut adalah alur pengerjaan saya:
- Apakah device yang digunakan oleh seorang mahasiswa tersebut?
  Setelah membuka **innerchild2.pcap**, saya membuka paket dengan keterangan "GET DESCRIPTOR Response CONFIGURATION" untuk mengetahui _device_ apa yang tersambung. Dan terdapat jawaban "Mouse".
  ![Kali Linux 2024 3 (Debian 12 x) 64-bit - VMware Workstation 22_09_2024 18_30_21](https://github.com/user-attachments/assets/a6017342-86c1-431c-bd04-c5a82b530bf6)
- Apakah device yang digunakan oleh seorang mahasiswa tersebut?
  Seharusnya pertanyaan tersebut menjadi "Kalimat apa yang dituliskan oleh mahasiswa tersebut?", setelah mencoba-coba berbagai _script_ untuk mengkonversi data tersebut baik menjadi output apapun itu. Muncul sebuah jawaban dengan mengubah kumpulan data tersebut menjadi serangkaian _stroke_ mouse yang digeser membentuk sebuah kata "HALO MAS KEVIN SALKEN".
### Benar! Ini flag-mu: `JarkomIT{d0n7_wr173_r4nd0m1y_nscPe60yXnhWP7bFogalr7gSpm45Ouo6usJpMWLyTQdYVeLX6HCCsK3v1n}`

## Stegography
Terdapat _challange_ dengan keterangan sebagai berikut, "Seekor stegosaurus berusaha menyimpan pesan di dalam beberapa gambar apakah kamu bisa memperoleh dan menyusunnya?". Berikut adalah alur pengerjaan saya:
- Ada berapa banyak gambar yang dikirim?
  Pada **image.pcap**, saya menggunakan filter `frame contains "png"` untuk mengetahui berapa gambar yang dikirim. Terdapat 13 gambar dengan ekstensi .png yang dikirim.
  ![Kali Linux 2024 3 (Debian 12 x) 64-bit - VMware Workstation 22_09_2024 18_40_46](https://github.com/user-attachments/assets/5a069cdb-cb71-4cff-a4fa-be657a46c413)
- Nama-nama file yang memiliki pesan? (Berurut abjad)
  Setelah membuka masing-masing gambar tersebut, ditemukan bahwa ATP.png mengandung kata tersembunyi "nawalhap"; EH.png mengandung kata "nanamaek"; KJK.png mengandung kata "rebis". Maka jawaban yang tepat adalah ATP, EH, KJK.
- Apa pesannya jika digabung?
  "pahlawan keamanan siber", karena kalimat tersebut tertulis secara terbalik. Maka setelah berbagai percobaan kata, jawabannya ditemukan.
### Benar! Ini flag-mu: `JarkomIT{S3LaM4t_p4rA_PahL4WaN_E3KALxrLHclXyT914408ZP3l2P5sj90oEV9yWdS0N3MB4X3pmK4ffhC5}`

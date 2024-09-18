# Jarkom-Modul-1-IT44-2024
| Nama                     | NRP         |
| -------------------------| ----------- |
| Diandra Naufal Abror     | 5027231004  |
| Acintya Edria Sudarsono  | 5027231020  |

Write Up Modul 1.
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
JarkomIT{8uK4n_S4n1ty_b1a5A_41pctZxGk6SeQyyvrznzm0LLuSu5V5GdC7fAfZoVK1zJXlfXm6JnPIKK}

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


# RIICHAT — Laporan Celah Keamanan & Panduan Perbaikan

| | |
|---|---|
| **Target** | `RIICHAT.apk` — `com.myapk.riichat` v1.2 (versionCode 1) |
| **SHA-256 APK** | `687a407f594d8f4b95872586d0289b054f7b4b8fd87a86bb80265348acb5038c` |
| **Backend** | `https://shofpdomluroolczfvkv.supabase.co` (Supabase REST + Storage) |
| **Tanggal audit** | 29 Oktober 2026 |
| **Metode** | Reverse engineering statis (jadx + apktool) dan uji runtime di AVD Android 14 + probe REST |
| **Status** | Temuan berlaku pada backend produksi dan sudah direproduksi |

> Dokumen ini ditujukan untuk developer. Tanda **(terverifikasi)** berarti ada bukti HTTP langsung saat audit; **(inferensi)** berarti disimpulkan dari kode/perilaku dan perlu dikonfirmasi.

---

## 1. Ringkasan eksekutif

RIICHAT adalah aplikasi WebView (±150 KB) yang seluruh logikanya ada di `assets/index.html` (di-`base64`), dengan backend Supabase. **Tidak ada autentikasi server sama sekali**:

- Login hanya mencocokkan `pass_hash` di sisi klien.
- Identitas disimpan di `localStorage.rc_uid` dan dikirim sebagai filter (`sender=eq.<uid>`, `owner=eq.<uid>`).
- Semua request memakai **publishable/anon key** yang tertanam di APK.

Akibatnya otorisasi sepenuhnya bergantung pada RLS Supabase — dan RLS-nya permisif. Saat audit, anon key bisa:

- membaca **semua** user (termasuk `pass_hash`), pesan, status, kontak, dan OTP;
- **mengubah user mana pun** (ganti nama/avatar/sandi) → **account takeover**;
- **membuat user baru dengan uid apa pun** (termasuk uid `1`);
- **mengirim pengumuman komunitas** dan **memberi centang biru** ke siapa pun.

Tiga akar masalah:

1. **Tidak ada identitas terverifikasi** — uid dikirim sendiri oleh client.
2. **RLS tidak membatasi tulis/baca** pada tabel sensitif.
3. **OTP dibuat di client** dan disimpan plaintext di tabel yang bisa dibaca publik.

### Daftar temuan

| ID | Temuan | Severity |
|---|---|---|
| K-01 | Tidak ada autentikasi server; identitas = uid di `localStorage` | **Kritis** |
| K-02 | Anon key bisa UPDATE user mana pun → account takeover | **Kritis** |
| K-03 | `pass_hash` terbaca publik + hashing lemah (SHA-256 1 iterasi) | **Kritis** |
| K-04 | OTP dibuat di client, disimpan plaintext, bisa dibaca/dihapus siapa pun | **Kritis** |
| T-01 | INSERT `riichat_users` terbuka → buat akun uid apa pun | **Tinggi** |
| T-02 | INSERT `riichat_community` terbuka → pengumuman palsu/phishing | **Tinggi** |
| T-03 | INSERT `riichat_verified_users` terbuka → centang biru palsu, tidak bisa dicabut | **Tinggi** |
| T-04 | Pesan/status/kontak terbaca semua (RLS SELECT terbuka) | **Tinggi** |
| T-05 | WebView: `allowUniversalAccessFromFileURLs`, `allowFileAccess`, TLS di-bypass, cleartext | **Tinggi** |
| T-06 | Path traversal pada JS bridge `AndroidDownloader` | **Tinggi** |
| S-01 | Bucket Storage `riichat` publik | **Sedang** |
| S-02 | Tidak ada rate limit / anti-spam; pesan & OTP menumpuk | **Sedang** |
| S-03 | Moderasi mustahil: DELETE/UPDATE komunitas ditolak untuk client | **Sedang** |
| R-01 | Self-signed release + distribusi sideload + compileSdk 28 | **Rendah** |

---

## 2. Arsitektur singkat

```
MainActivity (WebView fullscreen)
  └─ file:///android_asset/index.html   (base64 → HTML+CSS+JS)
       └─ fetch  https://<project>.supabase.co/rest/v1/*   (anon key)
       └─ fetch  https://<project>.supabase.co/storage/v1/* (bucket publik)
```

Tabel: `riichat_users`, `riichat_otps`, `riichat_contacts`, `riichat_messages`, `riichat_status`, `riichat_community`, `riichat_verified_users`.

`index.html` hanya di-`document.write(decodeURIComponent(escape(atob('...'))))` — **bukan proteksi**, cukup decode base64.

---

## 3. Matriks izin (hasil uji anon key)

| Tabel | SELECT | INSERT | UPDATE | DELETE |
|---|---|---|---|---|
| `riichat_users` | ✅ semua baris + `pass_hash` (terverifikasi) | ✅ (terverifikasi) | ✅ **semua baris** (terverifikasi) | belum diuji |
| `riichat_messages` | ✅ 307 baris (terverifikasi) | ✅ (terverifikasi via app) | ? inferensi | ? inferensi |
| `riichat_status` | ✅ 46 baris (terverifikasi) | ✅ (terverifikasi) | ? | ? |
| `riichat_contacts` | ✅ 21 baris (terverifikasi) | ✅ (terverifikasi via app) | ? | ? |
| `riichat_otps` | ✅ 20 baris + `code` (terverifikasi) | ✅ (terverifikasi) | ? | ✅ (terverifikasi via app) |
| `riichat_community` | ✅ 13 baris (terverifikasi) | ✅ (terverifikasi) | ❌ `200 []` (terverifikasi) | ❌ `204 */0` (terverifikasi) |
| `riichat_verified_users` | ✅ 5 baris (terverifikasi) | ✅ (terverifikasi) | ? | ❌ (terverifikasi) |

Angka baris = kondisi saat audit (berubah-ubah).

---

## 4. Detail temuan

### K-01 — Tidak ada autentikasi server, identitas hanya uid di localStorage

**Lokasi:** `index.html` baris 531–542 (login), 599–603 (sesi), 1320–1324 (auto-login) — setelah decode.
**Bukti:**
```js
me = {uid:u.uid, name:u.name, avatar:u.avatar};
localStorage.rc_uid = u.uid;          // satu-satunya "sesi"
```
```js
const id = localStorage.rc_uid;
const u = await sel(`riichat_users?uid=eq.${enc(id)}&select=uid,name,avatar`);
```
**Dampak:** tidak ada token/JWT. Siapa pun bisa memakai uid siapa pun; semua filter `sender=eq.<uid>` dapat dipalsukan. Tidak ada rate limit login.

**Perbaikan:** pindahkan autentikasi ke server (Supabase Auth, atau minimal RPC yang mengembalikan token acak berumur pendek). Jangan pernah memakai uid sebagai bukti identitas.

---

### K-02 — Anon key bisa mengubah user mana pun (account takeover)

**Lokasi:** `index.html` 1236–1263 (ganti avatar/nama/sandi).
**Bukti (terverifikasi):**
```http
PATCH /rest/v1/riichat_users?uid=eq.84073333
{"name":"Kepo2","name_key":"kepo2"}          → HTTP 200

PATCH /rest/v1/riichat_users?uid=eq.1
{"name":"Kepo","name_key":"kepo"}            → HTTP 200
```
Tidak ada header identitas selain anon key, dan dua uid berbeda berhasil diubah.

**Dampak:** penyerang bisa `PATCH ... {"pass_hash":"<sha256(uid:sandi:riichat)>"}` untuk **mengambil alih akun mana pun**, mengganti nama, atau mengosongkan avatar. Ini eskalasi paling berbahaya.

**Perbaikan (wajib):**
```sql
alter table public.riichat_users enable row level security;
revoke insert, update, delete on public.riichat_users from anon, authenticated;
-- tulis hanya via RPC/Edge Function yang memverifikasi sesi
```

---

### K-03 — `pass_hash` terbaca publik + hashing lemah

**Bukti (terverifikasi):**
```http
GET /rest/v1/riichat_users?uid=eq.1&select=uid,name,pass_hash
→ 200 [{"uid":"1","pass_hash":"26508833ac6f…c8d"}]
```
**Algoritma:** `SHA-256(uid + ":" + sandi + ":riichat")`, satu iterasi, tanpa pepper, salt = uid (dapat diprediksi).

**Dampak:** siapa pun bisa mengunduh seluruh hash (46 user) dan melakukan brute force offline. Sandi lemah akan cepat terbongkar; hash juga memungkinkan verifikasi tebakan tanpa menyentuh login.

**Perbaikan:**
- Cabut akses kolom:
  ```sql
  revoke select on public.riichat_users from anon, authenticated;
  grant select (uid, name, name_key, avatar, cover, created_at)
    on public.riichat_users to anon, authenticated;
  ```
- Migrasi ke bcrypt/argon2 (`crypt()` + `gen_salt('bf')` di pgcrypto), rehash saat login berikutnya.
- Login lewat RPC `SECURITY DEFINER`, jangan pernah mengirim `pass_hash` ke client.

---

### K-04 — OTP dibuat di client dan disimpan plaintext

**Lokasi:** `index.html` 543–571.
**Bukti (terverifikasi):**
```js
// #bOtp — kode dibuat di HP, bukan server
const a = new Uint32Array(2); crypto.getRandomValues(a);
const code = String((a[0]*4294967296 + a[1]) % 1e8).padStart(8,'0');
await del(`riichat_otps?name=eq.${enc(n)}`);
await ins('riichat_otps', [{name:n, code}]);

// #bVer — verifikasi hanya SELECT ke tabel
const r = await sel(`riichat_otps?name=eq.${enc(reg.name)}&code=eq.${c}&created_at=gte.${iso5h()}&select=id`);
```
```http
GET /rest/v1/riichat_otps?select=*        → 200, 20 baris (termasuk kolom code)
DELETE /rest/v1/riichat_otps?name=eq.<x>  → 204 (client memang menghapus OTP)
```
**Dampak:** "OTP dari admin" tidak pernah ada. Siapa pun bisa membaca kode OTP yang tertunda untuk nama apa pun, menghapusnya (DoS pendaftaran), atau mendaftar sendiri tanpa OTP. Audit juga membuktikan OTP bisa dipaksa statis (`66666666`) hanya dengan mengubah client.

**Perbaikan:** generate OTP di server (RPC), simpan **hash**-nya, expiry di server, batasi percobaan, kirim via kanal yang benar. Tabel OTP tidak boleh punya akses anon sama sekali.

---

### T-01 — INSERT user terbuka: uid apa pun bisa dibuat

**Bukti (terverifikasi):**
```http
POST /rest/v1/riichat_users
[{"uid":"1","name":"Kepo1","name_key":"kepo1","pass_hash":"2650…","avatar":null}]
→ HTTP 201
```
**Dampak:** uid resmi/pendek bisa diambil alih, akun spam massal, dan `name_key` sah bisa diduduki lebih dulu (squatting). Pengecekan 8 digit + unik hanya ada di client.

**Perbaikan:** uid harus dibuat server (`gen_random_uuid()` atau sequence), INSERT dicabut dari anon, nama divalidasi dan di-rate-limit di server.

---

### T-02 — Komunitas "hanya admin" hanya UI; INSERT terbuka

**Lokasi:** `index.html` 402–406 (footer), 759–784 (polling baca), tidak ada kode insert.
**Bukti (terverifikasi):**
```http
POST /rest/v1/riichat_community  [{"id":5,"body":"probe"}]
→ 409 duplicate key "riichat_community_pkey"
```
Error constraint (bukan `42501 permission denied`) membuktikan INSERT **lolos RLS**. Pesan uji nyata juga berhasil dibuat (id 6), dan pesan dari uid lain (id 7–13) muncul kemudian.

**Dampak:** siapa pun bisa menyiarkan "pengumuman resmi" — termasuk link APK phishing — ke semua pengguna, dengan tampilan rata tengah seperti admin. Klaim "Hanya admin yang dapat mengirim pesan" menyesatkan.

**Perbaikan:**
```sql
revoke insert, update, delete on public.riichat_community from anon, authenticated;
-- insert hanya service_role / RPC admin
```

---

### T-03 — Centang biru bisa ditulis siapa pun, tidak bisa dicabut

**Lokasi:** `index.html` 487–496 (`refreshVerified`), 489–492 (`isVerified`).
**Bukti (terverifikasi):**
```http
POST /rest/v1/riichat_verified_users [{"uid":"1"}]  → 201
DELETE /rest/v1/riichat_verified_users?uid=eq.1     → 204, content-range: */0 (tidak terhapus)
```
**Dampak:** badge "verified" bisa dipalsukan siapa saja dan **tidak bisa dicabut** dari client (hanya dashboard/service role). Badge ini dipakai untuk akun developer dan admin, sehingga sangat menyesatkan.

**Perbaikan:** cabut INSERT/UPDATE/DELETE dari anon; hanya `service_role`. Tampilkan badge hanya jika diverifikasi lewat kanal resmi.

---

### T-04 — Pesan, status, kontak terbaca semua

**Bukti (terverifikasi, agregat):**

| Tabel | Baris terlihat anon |
|---|---|
| `riichat_messages` | 307 |
| `riichat_status` | 46 |
| `riichat_contacts` | 21 |

Query count tanpa filter mengembalikan total seluruh tabel, artinya RLS tidak membatasi per pemilik. Filter `sender=eq.<uid>` hanya ada di client.

**Dampak:** kebocoran isi chat, daftar kontak, dan status (termasuk media). Filter privasi status (`index.html` 1071–1099) berjalan **setelah** semua data diunduh.

**Perbaikan (setelah Supabase Auth aktif):**
```sql
create policy msg_select on public.riichat_messages for select to authenticated
  using (auth.uid()::text in (sender, receiver));
create policy msg_insert on public.riichat_messages for insert to authenticated
  with check (auth.uid()::text = sender);
create policy status_select on public.riichat_status for select to authenticated
  using (auth.uid()::text = owner or exists (
    select 1 from public.riichat_contacts c
    where c.owner = auth.uid()::text and c.contact_uid = owner));
```

---

### T-05 — Konfigurasi WebView membuka akses file & mematikan TLS

**Lokasi:** `MainActivity.java` (`setupWebView`, `onReceivedSslError`), `AndroidManifest.xml`.
```java
settings.setAllowFileAccess(true);
settings.setAllowUniversalAccessFromFileURLs(true);
settings.setAllowFileAccessFromFileURLs(true);
settings.setMixedContentMode(0);
settings.setCacheMode(-1);
// ...
public void onReceivedSslError(WebView v, SslErrorHandler h, SslError e) { h.proceed(); }
```
```xml
android:usesCleartextTraffic="true"
```
**Dampak:** setiap XSS/bug di halaman bisa membaca file lokal aplikasi (`file:///data/data/...`) lalu mengirimnya keluar. Error TLS diterima, sehingga MITM bisa menyuntik konten ke WebView. Konten campuran HTTP diizinkan.

**Perbaikan:**
- `setAllowUniversalAccessFromFileURLs(false)`, `setAllowFileAccessFromFileURLs(false)`, `setAllowFileAccess(false)`.
- Sajikan aset lewat `WebViewAssetLoader` (https) atau server lokal.
- `onReceivedSslError` → `handler.cancel()`.
- `usesCleartextTraffic=false`, `mixedContentMode=NEVER_ALLOW`.
- Tambah CSP di `index.html` dan `setWebContentsDebuggingEnabled(false)` eksplisit untuk release.

---

### T-06 — Path traversal pada JS bridge `AndroidDownloader`

**Lokasi:** `MainActivity.processBase64DataUrl()`.
```java
String filename = ... /* dari parameter data URL, hanya URL-decode */
File out = new File(Environment.getExternalStoragePublicDirectory(
        Environment.DIRECTORY_DOWNLOADS), filename);
new FileOutputStream(out, false).write(Base64.decode(base64, 0));
```
Tidak ada sanitasi `../`, tidak ada validasi MIME/ukuran. JS apa pun di WebView bisa memanggil `AndroidDownloader.processBlobData(...)`.

**Dampak:** penulisan file arbitrer di direktori yang dapat ditulis aplikasi (di luar folder Downloads) — dapat menimpa konfigurasi/cache aplikasi.

**Perbaikan:** whitelist nama file (`[A-Za-z0-9._-]`), buang separator path, batasi ukuran, tulis lewat `MediaStore`, dan jangan ekspos bridge ini ke konten tak tepercaya.

---

### S-01 — Bucket Storage publik

URL media berformat `.../storage/v1/object/public/riichat/...` dan dapat diakses tanpa autentikasi (contoh status video pengguna). **Perbaikan:** bucket privat + signed URL + policy per pemilik.

---

### S-02 — Tidak ada rate limit / anti-spam

20 baris OTP tertunda, 307 pesan, dan komunitas bisa di-spam. Tidak ada throttling di client maupun bukti throttling di server. **Perbaikan:** rate limit di RPC/Edge Function (per IP/uid), batas panjang pesan, dan moderasi.

---

### S-03 — Moderasi tidak mungkin dari client

INSERT komunitas terbuka, tetapi UPDATE/DELETE ditolak (`200 []` / `204 */0`). Artinya spam/pesan uji **permanen** kecuali dihapus dari dashboard. **Perbaikan:** desain ulang izin: user boleh menghapus pesannya sendiri, admin boleh menghapus semua (via service role/RPC), dan sediakan audit log.

---

### R-01 — Rilis & distribusi

- APK ditandatangani self-signed `CN=RFPROJECT` (bukan Play App Signing).
- Distribusi lewat link MediaFire di pengumuman komunitas (sideload).
- `compileSdkVersion=28`, `targetSdkVersion=35`; setelan WebView lama dipertahankan.
**Perbaikan:** pakai Play App Signing/keystore rilis yang dijaga, publikasikan lewat Play Store, naikkan compileSdk, dan review setelan WebView.

---

## 5. Rencana perbaikan (urut prioritas)

### P0 — hari ini (bisa tanpa mengubah client)
1. Cabut tulis dari anon pada tabel sensitif:
   ```sql
   revoke insert, update, delete on public.riichat_users              from anon, authenticated;
   revoke insert, update, delete on public.riichat_community          from anon, authenticated;
   revoke insert, update, delete on public.riichat_verified_users     from anon, authenticated;
   revoke all                    on public.riichat_otps               from anon, authenticated;
   ```
2. Sembunyikan `pass_hash` (revoke kolom + grant kolom aman).
3. Ganti login menjadi RPC `SECURITY DEFINER` (contoh di bawah).
4. Rotasi/bersihkan artefak uji (lihat Lampiran).

> Catatan: langkah 1–2 akan memutus client v1.2 yang sekarang (login membaca `pass_hash`). Urutkan: deploy client baru → baru cabut izin, atau terima downtime singkat.

### P1 — minggu ini
5. Migrasi ke **Supabase Auth** (email/anon sign-in) atau token sesi sendiri; semua policy memakai `auth.uid()`.
6. RPC untuk kirim pesan/status/komunitas; client tidak lagi mengirim `sender`/`owner`.
7. Policy SELECT per pemilik untuk messages/status/contacts.
8. Storage privat + signed URL.
9. Hardening WebView (T-05) + sanitasi bridge (T-06).

### P2 — lanjutan
10. bcrypt/argon2 + rehash, rate limit, moderasi & audit log, E2E atau minimal enkripsi at-rest, Play App Signing.

---

## 6. Contoh SQL siap pakai

### 6.1 Login RPC (menggantikan SELECT `pass_hash` di client)

```sql
create extension if not exists pgcrypto;

create or replace function public.riichat_login(p_id text, p_pass text)
returns table(uid text, name text, avatar text)
language plpgsql security definer set search_path = public as $$
declare u public.riichat_users;
begin
  select * into u from public.riichat_users
   where uid = p_id or name_key = lower(p_id) limit 1;
  if not found then raise exception 'Akun tidak ditemukan'; end if;

  if u.pass_hash <> encode(digest(u.uid || ':' || p_pass || ':riichat','sha256'),'hex') then
    raise exception 'Sandi salah';
  end if;

  return query select u.uid, u.name, u.avatar;
end $$;

revoke all on function public.riichat_login(text,text) from public;
grant execute on function public.riichat_login(text,text) to anon;
```

### 6.2 Registrasi + OTP di server (garis besar)

```sql
-- OTP: generate di server, simpan hash, expiry di server
create table if not exists public.riichat_otps_srv (
  name text primary key,
  code_hash text not null,
  expires_at timestamptz not null default now() + interval '5 hours',
  attempts int not null default 0
);
revoke all on public.riichat_otps_srv from anon, authenticated;
```

`riichat_request_otp(name)` dan `riichat_register(name, code, pass, avatar)` dibuat `SECURITY DEFINER`, dengan rate limit per IP/nama dan `insert into riichat_users (uid, ...) values (gen_random_uuid()::text, ...)`.

### 6.3 Policy komunitas & verified (setelah Auth)

```sql
alter table public.riichat_community enable row level security;
create policy community_read on public.riichat_community
  for select to anon, authenticated using (true);
-- tidak ada policy insert/update/delete untuk anon/authenticated
-- tulis hanya service_role (dashboard/Edge Function)

alter table public.riichat_verified_users enable row level security;
create policy verified_read on public.riichat_verified_users
  for select to anon, authenticated using (true);
```

---

## 7. Checklist verifikasi setelah perbaikan

```bash
KEY=<anon key>
B=https://<project>.supabase.co/rest/v1

# harus 401/403
curl -s -o /dev/null -w "%{http_code}\n" -X POST "$B/riichat_community" \
  -H "apikey: $KEY" -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" -d '[{"body":"x"}]'

curl -s -o /dev/null -w "%{http_code}\n" -X POST "$B/riichat_verified_users" \
  -H "apikey: $KEY" -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" -d '[{"uid":"1"}]'

curl -s -o /dev/null -w "%{http_code}\n" -X PATCH "$B/riichat_users?uid=eq.1" \
  -H "apikey: $KEY" -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" -d '{"name":"x"}'

# pass_hash tidak boleh muncul
curl -s "$B/riichat_users?select=*&limit=1" -H "apikey: $KEY" -H "Authorization: Bearer $KEY"

# pesan user lain tidak boleh terbaca (setelah Auth)
curl -s "$B/riichat_messages?select=id&limit=1" -H "apikey: $KEY" -H "Authorization: Bearer $KEY"
```

Checklist manual:
- [ ] `pass_hash` tidak pernah dikirim ke client.
- [ ] uid dibuat server; client tidak bisa memilih uid.
- [ ] OTP tidak bisa dibaca/dihapus dari client.
- [ ] INSERT komunitas/verified ditolak untuk anon.
- [ ] UPDATE user hanya untuk pemiliknya.
- [ ] SELECT pesan/status/kontak hanya untuk pihak terkait.
- [ ] WebView tidak punya akses `file://` dan menolak TLS error.
- [ ] Bucket Storage tidak publik.
- [ ] `curl` di atas semuanya 401/403 atau kosong.

---

## 8. Lampiran

### 8.1 Artefak audit

| File | Keterangan | SHA-256 |
|---|---|---|
| `RIICHAT.apk` | APK asli | `687a407f…b5038c` |
| `work/decoded-original.html` | `assets/index.html` setelah decode base64 | — |
| `work/decoded.html` | hasil decode + patch uji (OTP statis, composer komunitas) | — |
| `work/RIICHAT-patched.apk` | build uji OTP statis | `26f57b70…95036` |
| `work/RIICHAT-community.apk` | build uji kirim komunitas | `ea714895…5db23` |
| `work/jadx/`, `work/apktool/` | hasil decompile | — |

### 8.2 Artefak uji yang perlu dibersihkan

Dibuat selama audit (hapus jika tidak dipakai):

```sql
delete from public.riichat_community      where id between 6 and 13;  -- pesan uji
delete from public.riichat_verified_users where uid = '1';            -- centang uji
delete from public.riichat_users          where uid in ('1','54624051');
-- akun uid 84073333 di-rename menjadi "Kepo2" saat audit;
-- kembalikan jika perlu:
update public.riichat_users set name='Kepo', name_key='kepo' where uid='84073333';
```

> `DELETE` untuk `riichat_community`/`riichat_verified_users` tidak bisa dilakukan dengan anon key — gunakan dashboard/service role.

### 8.3 Endpoint yang dipakai client

```
GET/POST/PATCH/DELETE  /rest/v1/riichat_users
GET/POST/PATCH/DELETE  /rest/v1/riichat_otps
GET/POST/PATCH/DELETE  /rest/v1/riichat_contacts
GET/POST/PATCH/DELETE  /rest/v1/riichat_messages
GET/POST/PATCH/DELETE  /rest/v1/riichat_status
GET/POST               /rest/v1/riichat_community
GET/POST               /rest/v1/riichat_verified_users
POST                   /storage/v1/object/riichat/<path>
GET                    /storage/v1/object/public/riichat/<path>
```

### 8.4 Batasan audit

- Fokus pada APK v1.2 dan backend yang dipakai APK tersebut.
- Tidak semua operasi tulis diuji (beberapa hanya inferensi dari kode) untuk menghindari perubahan data nyata.
- Tidak ada uji beban/rate limit dan tidak ada uji rekayasa sosial.
- Angka baris/uid berubah setelah audit karena aplikasi aktif dipakai.

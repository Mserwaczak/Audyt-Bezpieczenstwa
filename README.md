# Raport podatności znalezionych w aplikacji Node Goat


| Testowany system | Node Goat |
|:------: | :-----------: |
| Data wykonania | XII 2022 - I 2023 |
|  Miejsce wykonania audytu    | Kraków |
| Audytorzy wykonujący prace | Aleks Prochal, Michał Serwaczak, Jakub Sosin |
|  Wersja raportu    | 1.0 |

# 1.	Podsumowanie
Audyt aplikacji NodeGoat został zrealizowany w celu ustalenia zgodności ze standardem OWASP TOP 10. 
Stan zgodności aplikacji NodeGoat z OWASP Top 10 można uznać jako zły. W aplikacji znajduje się większość z dziesięciu najpopularniejszych błędów spotykanych w aplikacjach webowych.

# 2.	Zakres i cele
## 2.1 Cel
Celem audytu była wstępna weryfikacja spełniania przez aplikację standardu OWASP TOP 10, jest to dziesięć najpopularniejszych błędów spotykanych w aplikacjach webowych.

## 2.2	Wykonane czynności
W ramach audytu wykonano następujące czynności:
* Analiza błędów występujących w aplikacji
*	Rozmowy z deweloperami

## 2.3	Aplikacja NodeGoat
Aplikacja NodeGoat jest aplikacją webową, opartą o architekturę klient-serwer. Wykorzystuje m. in. Następujące technologie:
* Serwer HTTP
* MongoDB
* NodeJS

# 3. Znalezione podatności pod względem poziomu niebezpieczeństwa
<img src="images/wykres.png" width="750" height="500"  alt="Wykres"/>

# 4. Znalezione podatności

| $\color{grey}{\textrm{Nie stwierdzono}}$ |$\color{green}{\textrm{Niski}}$| $\color{yellow}{\textrm{Średni}}$ |$\color{red}{\textrm{Wysoki}}$|
|-|-|-|-|

| Numer | Opis |
| :------: | ----------- |
| A01:2021 Broken Access Control| <ul><li>$\color{red}{\textrm{Aplikacja wykorzystuje userid jako część adresu URL}}$</li><li>$\color{red}{\textrm{Możliwość dostępu do zasobów bez posiadania odpowiednich uprawnień}}$</li><li>$\color{yellow}{\textrm{	Istnieje możliwość podmiany linku na taki, który prowadzi w inne miejsce}}$</li></ul> |
| A02:2021 Cryptographic Failures| <ul><li>$\color{red}{\textrm{Aplikacja wykorzystuje protokół HTTP do komunikacji z serwerem.}}$</li><li>$\color{red}{\textrm{Aplikacja przechowuje wrażliwe dane osobiste użytkownika jako zwykły tekst, bez używania jakiegokolwiek szyfrowania.}}$</li>
| A03:2021 Injection| <ul><li>$\color{red}{\textrm{Możliwość wstrzyknięcia kodu JS}}$</li><li>$\color{red}{\textrm{Podatności XSS}}$</li>
| A04:2021 Insecure Design| <ul> <li>$\color{grey}{\textrm{Na razie nie stwierdzono}}$</li>
| A05:2021 Security Misconfiguration| <ul> <li>$\color{red}{\textrm{Domyślny nagłówek HTTP x-powered-by może ujawnić szczegóły implementacji atakującemu}}$</li> <li>$\color{green}{\textrm{Nie jest ustawiona domyślna nazwa sesji cookie}}$</li>
| A06:2021 Vulnerable and Outdated Components| <ul> <li>$\color{yellow}{\textrm{Wykorzystywane są przestarzałe wersje bibliotek, oraz instalowane takie, które nie są używane}}$</li> 
| A07:2021 Identification and Authentication Failures| <ul> <li>$\color{red}{\textrm{Hasło zapisane w bazie danych w postaci zwykłego tekstu}}$</li><li>$\color{yellow}{\textrm{Sesja pozostaje aktywna do momentu, gdy użytkownik jawnie się wyloguje}}$</li><li>$\color{yellow}{\textrm{Aplikacja nie wymusza silnego hasła}}$</li><li>$\color{green}{\textrm{Aplikacja precyzuje czy błędne jest hasło czy login}}$</li>
| A08:2021 Software and Data Integrity Failures| <ul> <li>$\color{grey}{\textrm{ Na razie nie stwierdzono }}$</li>
| A09:2021 Security Logging and Monitoring Failures| <ul> <li>$\color{yellow}{\textrm{Brak jakiegokolwiek logowania i monitoringu}}$</li>
| A10:2021 Server-Side Request Forgery (SSRF)| <ul> <li>$\color{red}{\textrm{Atakujący może zmienić parametry URL żeby wskazać na kontrolowaną przez siebie stronę internetową, aby wejść w interakcję z serwerem }}$</li>



# 5. Szczegóły


Audyt aplikacji NodeGoat wykonany na zaliczenie przedmiotu Bezpieczeństwo Systemów Informatycznych
# Raport podatności znalezionych w aplikacji Node Goat


| Testowany system | Node Goat |
|:------: | :-----------: |
| Data wykonania | XII 2022 - I 2023 |
|  Miejsce wykonania audytu    | Kraków |
| Audytorzy wykonujący prace | Aleks Prochal, Michał Serwaczak, Jakub Sosin |
|  Wersja raportu    | 1.0 |

# 1.	Podsumowanie
Audyt aplikacji RetireEasy (NodeGoat) został zrealizowany na podstawie dziesięciu najpopularniejszych błędów występujących w aplikacjach webowych - OWASP Top 10 2021. 
Stan zgodności aplikacji NodeGoat z OWASP Top 10 można uznać jako zły. W aplikacji znajdują się wszystkie najpopularniejsze błędy spotykane w aplikacjach webowych.

# 2.	Zakres i cele
## 2.1 Cel
Celem audytu było sprawdzenie czy w aplikacji występują błędy wymienione w OWASP Top 10 - jest to zbiór dziesięciu najpopularniejszych błędów w aplikacjach webowych.

## 2.2	Wykonane czynności
W ramach audytu wykonano następujące czynności:
* Analiza błędów występujących w aplikacji
* Rekomendacja sposobu naprawy błędów

## 2.3	Aplikacja NodeGoat
Aplikacja NodeGoat jest aplikacją webową, opartą o architekturę klient-serwer. Wykorzystuje m. in. Następujące technologie:
* MongoDB v2.1.18
* NodeJS v18.13.0

Aplikacja służy do zarządzania emeryturami pracowników.

## 2.4 Opis wdrożenia
Aplikacja została uruchomiona na lokalnej maszynie.

# 3. Znalezione podatności pod względem poziomu niebezpieczeństwa
<img src="images/wykres.png" width="750" height="500"  alt="Wykres"/>

# 4. Znalezione podatności

| $\color{grey}{\textrm{Nie stwierdzono}}$ |$\color{green}{\textrm{Niski}}$| $\color{yellow}{\textrm{Średni}}$ |$\color{red}{\textrm{Wysoki}}$|
|-|-|-|-|

| Numer | Opis |
| :------: | ----------- |
| A01:2021 Broken Access Control| <ul><li>$\color{red}{\textrm{Aplikacja wykorzystuje userid jako część adresu URL}}$</li><li>$\color{red}{\textrm{Możliwość dostępu do zasobów bez posiadania odpowiednich uprawnień}}$</li></ul> |
| A02:2021 Cryptographic Failures| <ul><li>$\color{red}{\textrm{Aplikacja wykorzystuje protokół HTTP do komunikacji z serwerem.}}$</li><li>$\color{red}{\textrm{Aplikacja przechowuje wrażliwe dane osobiste użytkownika jako zwykły tekst, bez używania jakiegokolwiek szyfrowania.}}$</li>
| A03:2021 Injection| <ul><li>$\color{red}{\textrm{Możliwość wstrzyknięcia kodu JS}}$</li><li>$\color{red}{\textrm{Podatności XSS}}$</li>
| A04:2021 Insecure Design| <ul><li>$\color{red}{\textrm{Brak stosowania algorytmów szyfrujących}}$</li><li>$\color{green}{\textrm{Brak wygaśnięcia sesji użytkownika}}$</li>
| A05:2021 Security Misconfiguration| <ul> <li>$\color{green}{\textrm{Domyślny nagłówek HTTP x-powered-by może ujawnić szczegóły implementacji atakującemu}}$</li>|
| A06:2021 Vulnerable and Outdated Components| <ul> <li>$\color{yellow}{\textrm{Wykorzystywane są przestarzałe wersje bibliotek, oraz instalowane takie, które nie są używane}}$</li> 
| A07:2021 Identification and Authentication Failures| <ul> <li>$\color{red}{\textrm{Hasło zapisane w bazie danych w postaci zwykłego tekstu}}$</li><li>$\color{red}{\textrm{Sesja pozostaje aktywna do momentu, gdy użytkownik jawnie się wyloguje}}$</li><li>$\color{yellow}{\textrm{Aplikacja nie wymusza silnego hasła}}$</li><li>$\color{green}{\textrm{Aplikacja precyzuje czy błędne jest hasło czy login}}$</li>
| A08:2021 Software and Data Integrity Failures| <ul> <li>$\color{green}{\textrm{ Brak weryfikacji integralności  }}$</li>
| A09:2021 Security Logging and Monitoring Failures| <ul> <li>$\color{yellow}{\textrm{Brak jakiegokolwiek logowania i monitoringu}}$</li>
| A10:2021 Server-Side Request Forgery (SSRF)| <ul> <li>$\color{red}{\textrm{Atakujący może zmienić parametry URL żeby wskazać na kontrolowaną przez siebie stronę internetową, aby wejść w interakcję z serwerem }}$</li>



# 5. Szczegóły
## A01:2021 Broken Access Control
Kategoria podatności opisująca błędy dostępu. Kontrola dostępu egzekwuje politykę w taki sposób, aby użytkownicy nie mogli działać poza swoimi zamierzonymi uprawnieniami. Nieprawidłowości prowadzą zazwyczaj do nieuprawnionego ujawnienia informacji, modyfikacji lub zniszczenia wszystkich danych.
|||
|:------: | ----------- |
| Opis podatności | Aplikacja NodeGoat używa `userid` jako części adresu `URL`, oraz nie sprawdza czy użytkownik jest uprawniony do przeglądania strony docelowej. Widoczne jest to w module Allocations. Napastnik jest w stanie zmodyfikować adres `URL` i uzyskać informacje o alokacjach innych użytkowników. |
| Zrzuty ekranowe |W `routes/allocations.js`, NodeGoat pobiera `id` użytkownika z adresu url, aby pobrać alokacje. <img src='images/A1_3.png'/> <br/> W pasku przeglądarki widnieje następujący adres `URL`: `http://127.0.0.1:4000/allocations/2` <br /><br/> <img src='images/A1_1.png'/> <br/> Wytarczy zmienić adres na przykładowo: `http://127.0.0.1:4000/allocations/3` aby uzyskać nieautoryzowany dostęp do danych innego użytkownika <br/><img src='images/A1_2.png'/> <br/>  |
| Poziom niebezpieczeństwa	 | $\color{red}{\textrm{WYSOKI}}$  |
| Rekomendacje	 | <ul><li>Bezpieczniej jest zawsze pobierać alokacje dla zalogowanego użytkownika (używając `req.session.userId`) zamiast pobierać je z adresu url.</li><li>Każde użycie bezpośredniego odwołania do obiektu z niezaufanego źródła musi zawierać sprawdzenie kontroli dostępu, aby zapewnić, że użytkownik jest upoważniony do żądanego obiektu.</li> <li>Nie eksponować kluczy bazy danych, jako części linku</li></ul> |
|||

|||
|:------: | ----------- |
| Opis podatności | W aplikacji NodeGoat w module `Benefits`, zwykły użytkownik może uzyskać dostęp do zasobów przeznaczonych tylko dla Administratora. Dzięki temu może on je zmienić bez posiadania odpowiednich uprawnień|
| Zrzuty ekranowe |  W aplikacji NodeGoat, luka ta występuje w module `Benefits`, który umożliwia zmianę daty rozpoczęcia wypłaty świadczeń dla pracowników. Link do modułu świadczeń jest widoczny tylko dla Administratora <br/> <img src='images/A1_4.png'> <br/> W Aplikacji NodeGoat nie ma sprawdzania autoryzacji dla tras związanych z benefits w `routes/index.js` <br/> <img src='images/A1_6.png'/> <br/> Standardowy użytkownik domyślnie nie posiada dostępu do tego modułu: <br/> <img src='images/A1_5.png'/> <br/> Natomiast wystarczy wprowadzić w pasku `URL` adres: `http://127.0.0.1:4000/benefits` co spowoduje bezpośrednie dostanie się do strony Administratora. <br/> <img src='images/A1_4.png'/>|
| Poziom niebezpieczeństwa	 | $\color{red}{\textrm{WYSOKI}}$  |
| Rekomendacje	 | <ul><li>Można to naprawić, dodając middleware do weryfikacji roli użytkownika – sprawdzenia czy użytkownik jest zalogowany jako admin</li></ul> |
|||

## A02:2021 Cryptographic Failures
Podatność ta umożliwia napastnikowi dostęp do wrażliwych danych. Utrata takich danych może spowodować poważne skutki biznesowe i utratę reputacji. Wrażliwe dane zasługują na dodatkową ochronę, taką jak szyfrowanie, a także specjalne środki ostrożności podczas wymiany z przeglądarką. Jeśli napastnik uzyska dostęp do bazy danych aplikacji, może wykraść wrażliwe informacje niezaszyfrowane lub zaszyfrowane słabym algorytmem szyfrowania.
|||
|:------: | ----------- |
| Opis podatności |Aplikacja NodeGoat wykorzystuje protokół HTTP do komunikacji z serwerem. Jest to protokół nieszyfrowany, może on być podatny na przechwycenie danych |
| Zrzuty ekranowe |  W aplikacji NodeGoat wykorzystuje się niezabezpieczone połączenie HTTP <br/> <img src='images/1.png'/> <br/>|
| Poziom niebezpieczeństwa	 | $\color{red}{\textrm{WYSOKI}}$  |
| Rekomendacje	 | <ul><li>Należy wykorzystać bezpieczniejszy, zaszyfrowany protokół HTTPS</li></ul> |
|||

|||
|:------: | ----------- |
| Opis podatności |Aplikacja NodeGoat w żaden sposób nie szyfruje danych przechowywanych w bazie danych. Wszystkie hasła przechowywane są w postaci zwykłego tekstu. W przypadku przechwycenia ich przez napastnika, nie miałby on żadnego problemu z ich wykorzystaniem, ponieważ nie są one w żaden sposób zaszyfrowane. |
| Zrzuty ekranowe |  Niezabezpieczone dane użytkownika trzymane są w bazie danych w postaci zwykłego tekstu <br/><img src='images/2.png'/>|
| Poziom niebezpieczeństwa	 | $\color{red}{\textrm{WYSOKI}}$  |
| Rekomendacje	 | <ul><li>Szyfrować wszystkie dane wrażliwe</li> <li>Do szyfrowania haseł wykorzystać na przykład Argon2 lub Bcrypt</li></ul> |
|||

## A03:2021 Injection
Kategoria podatności, dzięki którym napastnicy mogą wstrzyknąć różnego typu polecenia, co spowoduje wykonanie ich po stronie serwera.
|||
|:------: | ----------- |
| Opis podatności | W aplikacji NodeGoat wykorzystywana jest funkcja `eval()` w celu przetwarzania danych wejściowych. Nie występuje jakakolwiek walidacja. Może to zostać wykorzystane przez atakującego do wstrzyknięcia i wykonania złośliwego kodu JavaScript na serwerze. Innym potencjalnym celem atakującego może być odczytanie zawartości plików z serwera. |
| Zrzuty ekranowe |  W `routes/contributions.js`, funkcja `handleContributionsUpdate()` w sposób niezabezpieczony używa `eval()` do konwersji kwot składek podanych przez użytkownika na liczby całkowite. <br/> <img src='images/7.png'/> <br/> Atakujący może wyłączyć serwer poprzez wykonanie polecenia: `process.exit()` <img src='images/3.png'/> <br/> Po kliknięciu przycisku `SUBMIT` nastąpiło zabicie procesu, serwer przestał działać <br/><img src='images/4.png'/> <br/> Wpisanie w okienko `while(true)` spowodowałoby całkowite wykorzystanie procesora, serwer nie byłby w stanie przetworzyć żadnych innych przychodzących żądań do czasu zrestartowania serwera. <br/>Atakujący może także odczytać zawartość katalogu znajdującego się na serwerze poprzez zastosowanie polecenia: `res.end(require('fs').readdirSync('.').toString())` <br/> <img src='images/5.png'/> <br/> <img src='images/6.png'/> <br/> |
| Poziom niebezpieczeństwa	 | $\color{red}{\textrm{WYSOKI}}$  |
| Rekomendacje	 | <ul><li>Walidować dane wejściowe po stronie serwera przed przetworzeniem ich</li> <li>Do parsowania danych wejściowych JSON, zamiast `eval()`, użyć bezpieczniejszej alternatywy takiej jak `JSON.parse()`. Do konwersji typów użyć metod parseXXX() związanych z typami.</li></ul> |
|||

|||
|:------: | ----------- |
| Opis podatności | Błędy XSS (Cross-site scripting) pojawiają się, gdy aplikacja pobiera niezaufane dane i wysyła je do przeglądarki internetowej bez odpowiedniej walidacji. XSS pozwala atakującym na wykonanie skryptów w przeglądarce ofiary, które mogą uzyskać dostęp do wszelkich ciasteczek, tokenów sesji lub innych wrażliwych informacji przechowywanych przez przeglądarkę, lub przekierować użytkownika na złośliwe strony. |
| Zrzuty ekranowe | W aplikacji NodeGoat nie jest ustawiona flaga HTTPonly dla cookie (Flaga HttpOnly wpływa na bezpieczeństwo w ten sposób, że blokuje próby odczytu cookie z tą flagą przez API inne niż HTTP) <br/> <img src='images/XSSc.png'/> <br/> NodeGoat jest podatna na Stored XSS (najbardziej złowroga odmiana, polegająca na umieszczeniu kodu javascript po stronie serwerowej)  w formularzu profili. Podczas wysyłania formularza, wartości pól imię i nazwisko są przesyłane do serwera i bez żadnej walidacji są zapisywane w bazie danych. Wartości te są następnie wysyłane z powrotem do przeglądarki bez żadnej walidacji i wyświetlane w prawym górnym rogu strony. <br/> <img src='images/XSS1.png'/> <br/> Użytkownik może zmienić imię lub nazwisko na na przykład `<script>alert(document.cookie)</script>` <br/> <img src='images/XSS2.png'/> <br/> Dzięki czemu może uzyskać informacje <br/> <img src='images/XSS3.png'/>  <br/> Ponadto opcja `autoescape` jest ustawiona na `false`, przez co aplikacja jest bardzie narażona na ataki XSS <br /> <img src='images/XSS4.PNG'/>  |
| Poziom niebezpieczeństwa	 | $\color{red}{\textrm{WYSOKI}}$  |
| Rekomendacje	 | <ul><li> Ustawić flagę HTTPOnly dla cookie sesji podczas konfiguracji sesji express</li> <li>Ustawić opcję autoescape na true</li> </ul> |
|||

## A04:2021 Insecure Design
Kategoria błędów która koncentruje się na zagrożeniach wynikających z wad projektowych i architektonicznych. Kategoria promuje użycie sprawdzonych, bezpiecznych wzorców projektowych oraz architektury referencyjnej.
|||
|:------: | ----------- |
| Opis podatności | W aplikacji NodeGoat nie zastosowano algorytmów szyfrujących dla haseł. W wyniku wycieku danych dostęp do kont użytkowników jest znacznie ułatwiony. |
| Zrzuty ekranowe |W obiekcie, który przechowuje dane użytkownika, hasło jest zapisane w niezabezpieczonej postaci <br/> <img src='images/A4_1.PNG'/> |
| Poziom niebezpieczeństwa | $\color{red}{\textrm{WYSOKI}}$  |
| Rekomendacje | <ul><li> Zastosowanie algorytmu szyfrującego np. bcrypt </li> <li> Zastosowanie metody „salting”, która dodaje losowe dane do haseł w celu ochrony </li>
|||

|||
|:------: | ----------- |
| Opis podatności |Twórcy aplikacji nie uwzględnili możliwości zakończenia (wygaśnięcia) sesji użytkownika.  W przypadku, gdy użytkownik nie wyloguje się, istnieje zagrożenie iż dostęp do jego konta mogą uzyskać inne osoby.|
| Poziom niebezpieczeństwa	 | $\color{green}{\textrm{NISKI}}$  |
| Rekomendacje	 | <ul><li>Stworzenie mechanizmu, który sprawi iż sesja użytkownika wygaśnie w momencie gdy użytkownik nie podejmie przez określony czas czynności, lub gdy przełączy on stronę  </li> </ul> |
|||

## A05:2021 Security Misconfiguration
Ta luka pozwala atakującemu na dostęp do domyślnych kont, nieużywanych stron, niezałatanych dziur, niezabezpieczonych plików i katalogów, itp. w celu uzyskania nieautoryzowanego dostępu lub wiedzy o systemie. <br/> Nieprawidłowa konfiguracja bezpieczeństwa może zdarzyć się na każdym poziomie aplikacji, w tym platformy, serwera WWW, serwera aplikacji, bazy danych, frameworka i kodu własnego.
|||
|:------: | ----------- |
| Opis podatności | Dzięki narzędziom dewelopera, każdy użytkownik można zauważyć nagłówek `X-powered-by`. Nagłówek ten może ujawnić szczegóły implementacji atakującemu. Backend jest wspierany przez Express.|
| Zrzuty ekranowe | Domyślny nagłówek HTTP x-powered-by może ujawnić szczegóły implementacji atakującemu. <br/> <img src='images/8.png'/> <br/> |
| Poziom niebezpieczeństwa	 | $\color{green}{\textrm{NISKI}}$  |
| Rekomendacje	 | <ul><li>Używać najnowszych stabilnych wersji node.js i express</li> <li>Wywołać metodę `app.disable('x-powered-by')` w celu nie wyświetlania zbędnych nagłówków </li> </ul> |
|||
  
## A06:2021 Vulnerable and Outdated Components
Komponenty, takie jak biblioteki, frameworki i inne moduły oprogramowania, prawie zawsze działają z pełnymi uprawnieniami. Jeżeli podatny komponent zostanie wykorzystany, taki atak może wywołać poważną utratę danych lub przejęcie serwera. Aplikacje wykorzystujące komponenty o znanych lukach mogą osłabić mechanizmy obronne aplikacji i umożliwić szereg możliwych ataków i skutków.
|||
|:------: | ----------- |
| Opis podatności | W aplikacji NodeGoat występują liczne przestarzałe i podatne komponenty. Instaluje ona również pakiety z których w rzeczywistości nie korzysta |
| Zrzuty ekranowe | Wykonano polecenie `npm audit` i stwierdzono wiele podatności. Polecenie audit przesyła opis zależności skonfigurowanych w projekcie do domyślnego rejestru i prosi o raport znanych podatności. Jeśli jakieś podatności zostaną znalezione, wtedy zostanie obliczony wpływ i odpowiednie środki zaradcze. <br/> <img src='images/A6_1.png'/> <br /> Przykładowe znalezione podatności <img src='images/A6_2.png'/> <br/> <img src='images/A6_3.png'/> <br/> Wykorzystano także narzędzie `npm-check`, wynik jego działania przedstawiony jest na zdjęciu poniżej <br/> <img src='images/A6_4.PNG'/> <br /> Wykorzystano także narzędzie snyk.io, fragment raportu: <br />  <img src='images/A6_5.PNG'/>|
| Poziom niebezpieczeństwa	 | $\color{yellow}{\textrm{ŚREDNI}}$  |
| Rekomendacje	 | <ul><li>Usunąć nieużywane zależności, niepotrzebne funkcje, komponenty i pliki.</li> <li>Należy pozyskiwać komponenty tylko z oficjalnych źródeł poprzez bezpieczne odnośniki</li> <li>Nie korzystać z bibliotek i komponentów, które nie są utrzymywane lub nie są tworzone łaty bezpieczeństwa dla starszych wersji.</li></ul> |
|||
  
## A07:2021 Identification and Authentication Failures
Potwierdzenie tożsamości użytkownika, uwierzytelnienie i zarządzanie sesją jest kluczowe dla ochrony przed atakami. Błędy tej kategorii mogą prowadzić do kradzieży danych. 
|||
|:------: | ----------- |
| Opis podatności | Aplikacja NodeGoat w żaden sposób nie szyfruje haseł przechowywanych w bazie danych. Są one przechowywane w postaci zwykłego tekstu. Ponadto aplikacja NodeGoat nie posiada mechanizmu służącego do odzyskiwania czy resetowania hasła. |
| Zrzuty ekranowe | Na zdjęciu widoczne jest, że hasła przechowywane są w bazie danych przy pomocy zwykłego tekstu bez jakiegokolwiek szyfrowania <br /> <br/> Obiekt odpowiedzialny za przechowanie danych użytkownika: <br /> <img src='images/A7_1_1.png'/> <br /> Użytkownicy przechowywani w bazie danych: <br /> <img src='images/A7_1_2.png'/> |
| Poziom niebezpieczeństwa	 | $\color{red}{\textrm{WYSOKI}}$  |
| Rekomendacje	 | <ul><li> Należy szyfrować hasła przechowywane w bazie danych przy pomocy `argon2` lub `bcrypt` </li></ul> |
|||

|||
|:------: | ----------- |
| Opis podatności | W aplikacji NodeGoat nie występuje żaden mechanizm zarządzania sesją. Sesja pozostaje aktywna do momentu, gdy użytkownik jawnie się wyloguje. Ponadto, aplikacja nie zapobiega dostępowi do ciasteczek w skrypcie, co czyni ją podatną na ataki Cross Site Scripting (XSS). Nie zapobiega się również wysyłaniu ciasteczek przy pomocy niezabezpieczonego połączenia HTTP. Aplikacja nie generuje identyfikatora sesji po zalogowaniu się użytkownika|
| Poziom niebezpieczeństwa	 | $\color{red}{\textrm{WYSOKI}}$  |
| Rekomendacje	 | <ul><li> Sesja użytkownika powinna być kończona zawsze gdy użytkownik wyłączy przeglądarkę, lub po jakimś określonym czasie </li> <li>Identyfikator sesji powinien być generowany podczas każdego logowania</li> <li>Należy chronić ciasteczka przed atakami XSS</li></ul> |
|||

|||
|:------: | ----------- |
| Opis podatności | W audytowanej aplikacji nie jest wymagane stosowanie silnych haseł. Możliwe jest nawet utworzenie hasła składającego się tylko z jednego znaku. Napastnik może wykorzystać tę lukę poprzez zgadywanie haseł metodą brute force.|
| Zrzuty ekranowe | Aplikacja NodeGoat nie wymusza silnego hasła. <br/> <img src='images/A7_2_1.png'/> <br/> regex dla egzekwowania hasła jest po prostu słaby (jedyne wymaganie to od 1 do 20 znaków) |
| Poziom niebezpieczeństwa	 | $\color{yellow}{\textrm{ŚREDNI}}$  |
| Rekomendacje	 | <ul><li> Minimalna długość hasła powinna wynosić co najmniej osiem znaków. Połączenie tej długości ze złożonością sprawia, że hasło jest trudne do odgadnięcia </li> <li>Złożoność hasła - Znaki hasła powinny być kombinacją znaków alfanumerycznych. Znaki alfanumeryczne składają się z liter, cyfr, znaków interpunkcyjnych, symboli matematycznych</li></ul> |
|||

|||
|:------: | ----------- |
| Opis podatności | W przypadku nieudanej próby logowania aplikacja w jawny sposób wymienia, który element był błędny: login czy hasło |
| Zrzuty ekranowe | W funkcji `handleLoginRequest()` wymieniane jest czy hasło było nieprawidłowe lub czy użytkownik nie istnieje. <br/> <img src='images/A9.png'/> <br /> Błędny użytkownik: <br /> <img src='images/A7_2_3.PNG'/> <br /> Błędne hasło: <br/> <img src='images/A7_2_4.PNG'/>|
| Poziom niebezpieczeństwa	 | $\color{green}{\textrm{NISKI}}$|
| Rekomendacje	 | <ul><li>Odpowiedzi na niepowodzenie uwierzytelnienia nie powinny wskazywać, która część danych uwierzytelniających była nieprawidłowa. Na przykład, zamiast "Nieprawidłowa nazwa użytkownika" lub "Nieprawidłowe hasło", wystarczy użyć "Nieprawidłowa nazwa użytkownika i/lub hasło"</li></ul> |
|||

## A08:2021 Software and Data Integrity Failures
Złożone aplikację, często wykorzystują zewnętrze biblioteki, paczki lub moduły. Weryfikacja integralności jest ważnym elementem pozwalającym uniknąć zagrożeń.
|||
|:------: | ----------- |
| Opis podatności | Wersje pakietów są zapisywane domyślnie w pliku package.json. Prefiks (^) oznacza aktualizacje do najnowszego wydania obeecnej wersji. Gdy usunięty zostanie plik package-lock.json oraz folder node_modules, możliwe jest wykonanie polecenie `npm install` oraz aktualizacja paczek. Cyberprzestępca może to wykorzystać, poprzez publikację nowej wersji paczki ze złośliwym kodem. |
| Zrzuty ekranowe | Zawartość package.json <br /> <img src='images/A8.PNG'/> |
| Poziom niebezpieczeństwa | $\color{green}{\textrm{NISKI}}$ |	 
| Rekomendacje	 | <ul><li> Korzystać z dokładnie określonych wersji pakietów </li><li> Dodanie w pliku package.json `save-exact=true`, co zagwarantuje, że NPM zainstaluje dokładnie wskazaną wersję </li> |
|||

## A09:2021 Security Logging & Monitoring Failures
Ta kategoria ma pomóc w wykrywaniu, eskalacji i reagowaniu na aktywne naruszenia. Bez logowania i monitorowania nie można wykryć naruszeń. Dzięki logom można także łatwiej naprawić błędy.
|||
|:------: | ----------- |
| Opis podatności | Aplikacja NodeGoat nie posiada praktycznie żadnych logów. Bez nich nie można stwierdzić czy wystąpił atak czy go nie było. Jeśli aplikacja popsułaby się, nie będzie wiadomo która konkretnie jej część jest wadliwa. Bez logowania i monitorowania nie da się wykryć naruszeń. <br/>Tylko dysponując logami można:<ul><li>	Poinformować użytkowników o błędach </li> <li>	Zgłosić organom ścigania włamanie </li></ul>|
| Zrzuty ekranowe | Przykładowo w funkcji `handleLoginRequest()` nie występują jakiekolwiek logi odnoszące się do prób logowania: <br/> <img src='images/A9.png'/> <br/> Administrator nie będzie wiedział czy podjęto próbę włamania |
| Poziom niebezpieczeństwa	 | $\color{yellow}{\textrm{ŚREDNI}}$|
| Rekomendacje	 | <ul><li> Należy upewnić się, że wszystkie błędy logowania, kontroli dostępu i walidacji danych wejściowych po stronie serwera mogą być rejestrowane  i przechowywane przez wystarczająco długi czas, aby umożliwić przeprowadzenie analizy kryminalnej </li> <li>Korzystać z aplikacji do logowania i monitorowania takich jak: LogRocket, RayGun czy Rollbar</li></ul> |
|||

## A10:2021 Server-Side Request Forgery (SSRF)
Błędy SSRF występują, gdy aplikacja internetowa pobiera zdalny zasób bez sprawdzania poprawności adresu URL dostarczonego przez użytkownika. W ataku SSRF atakujący może nadużywać funkcjonalności na serwerze do odczytu lub aktualizacji zasobów wewnętrznych. Atakujący może dostarczyć lub zmodyfikować adres URL, z którego kod uruchomiony na serwerze będzie odczytywał lub przesyłał dane, a poprzez staranne dobranie adresów URL atakujący może być w stanie odczytać konfigurację serwera 
|||
|:------: | ----------- |
| Opis podatności | W aplikaji NodeGoat możliwe jest przechwycenie adresu URL oraz jego zmodyfikowanie na inny, przez co możliwe jest odczytanie informacji o konfiguracji serwera.|
| Zrzuty ekranowe | Napastnik może wykorzystać lukę SSRF jako sposób na zebranie informacji o serwerze i sieci lokalnej. Na przykład, na stronie `/research` w aplikacji, użytkownik podaje symbol akcji. Symbol akcji jest łączony z adresem URL Yahoo, a serwer pobiera odpowiedź i wyświetla stronę. <br/> <img src='images/A10_1.png'/> <br/>  Użytkownik podaje symbol giełdowy: <br/> <img src='images/A10_2.png'/> <br/> Następnie zostaje przekierowany na następującą stronę <br/> <img src='images/A10_3.png'/> <br/> Atakujący może zmienić adres URL lub symbol <br/> Przed: <br /> <img src='images/A10_4.png'/> <br/> Po: <br /> <img src='images/A10_5.png'/> <br /> Dzięki czemu może uzyskać informacje o serwerze <br/> <img src='images/A10_6.png'/> <br/>  |
| Poziom niebezpieczeństwa	 | $\color{red}{\textrm{WYSOKI}}$|
| Rekomendacje	 | <ul><li> Należy sprawdzać rozszerzenie przez parsowanie URL-a</li> <li> Każde dane wejściowe przyjęte od użytkownika powinny zostać zweryfikowane i odrzucone, jeśli nie odpowiadają oczekiwanej pozytywnej identyfikacji. </li></ul> |
|||

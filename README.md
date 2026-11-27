# WinGames · Gestionale Alfa

Prima alfa mobile-first per la registrazione degli acconti, la stampa della ricevuta e l'importazione del sinottico AWP/VLT.

## Funzioni disponibili

- App web responsive installabile su Android come PWA.
- Registrazione acconto con locale, importo, data/ora automatica, esattore e nota facoltativa.
- Ricevuta stampabile con intestazione aziendale, locale, data/ora, importo ed esattore; stampa con browser verso stampanti Android Bluetooth/rete.
- Gestione anagrafica esattori e configurazione dell'intestazione.
- Importazione `.xlsx`, `.xls` o `.csv` con riconoscimento dei campi principali del sinottico.
- Elenco apparecchi con codice, sede, comune, modello, stato e contatori.
- Lettura QR tramite fotocamera del dispositivo (richiede HTTPS e browser con `BarcodeDetector`).
- Memorizzazione locale e shell applicativa utilizzabile senza connessione dopo il primo caricamento.

## Avvio

```sh
npm install
npm run dev
```

Build per hosting statico:

```sh
npm run build
```

## Importazione sinottico

Da **Anagrafica** o **Apparecchi**, selezionare il file ricevuto dall'ufficio. L'alfa usa il primo foglio e si aspetta intestazioni quali `CODEID`, `DENOMIN. SEDE`, `COMUNE`, `MODELLO`, `CODICE MODELLO`, `CNTTOTIN` e `CNTTOTOT`. I campi originali vengono mantenuti insieme alla vista normalizzata. Un nuovo import sostituisce l'elenco macchina presente sul dispositivo.

## Limiti alfa

I dati vengono conservati nel browser del singolo dispositivo. In questa versione telefono e ufficio non condividono automaticamente gli stessi movimenti: per lavorare con un archivio aziendale unico servono API, database, autenticazione, ruoli e sincronizzazione. La ricevuta stampata è una ricevuta gestionale di cortesia, non un documento fiscale. La lettura QR apre la scheda della macchina per il codice acquisito; non legge i contatori dall'apparecchio. L'acquisizione automatica dei contatori dipende dagli apparecchi, dai protocolli e dal contenuto dei QR effettivamente in uso.

Il sinottico aziendale non è incluso nel repository: caricarlo manualmente dalla sezione anagrafica evita di pubblicare dati operativi dei locali e degli apparecchi.

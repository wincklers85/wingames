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
- Memorizzazione locale e utilizzo durante i giri anche senza connessione dopo il primo caricamento.

## Avvio

```sh
npm install
npm run dev
```

Build per hosting statico: `npm run build`.

## Limiti alfa

I dati restano nel browser del singolo dispositivo. Telefono e ufficio non condividono automaticamente gli stessi movimenti; per un archivio comune servono API, database, autenticazione, ruoli e sincronizzazione. La ricevuta stampata è gestionale di cortesia, non documento fiscale. La lettura QR apre il codice in ricerca; non acquisisce contatori automaticamente. Il sinottico non è incluso nel repository.

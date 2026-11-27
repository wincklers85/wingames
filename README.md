# WinGames — gestionale alfa

PWA aziendale per Funseven Technology. Questa prima versione gestisce accessi, dispositivi autorizzati, anagrafica importata da sinottico e registrazione/stampa degli acconti.

## Funzioni alfa

- Login con account amministratore ed esattori.
- Creazione e disattivazione degli account da parte dell'amministratore.
- Associazione del telefono con codice monouso o QR e revoca del dispositivo.
- Importazione Excel del sinottico: codice apparecchio, locale, comune, indirizzo, modello, esercente, stato e contatori.
- Registrazione dell'acconto con data/ora ed esattore ricavati dal server; ricevuta stampabile dal telefono.
- Archivio aziendale condiviso tramite Cloudflare D1. Non caricare sinottici o credenziali in questo repository.

## Avvio iniziale

L'applicazione viene pubblicata come sito installabile da Chrome su Android (Aggiungi a schermata Home). Al primo accesso, il proprietario del deployment crea l'amministratore usando il codice iniziale configurato come segreto `WG_BOOTSTRAP_KEY`; la sessione usa il segreto `WG_SESSION_SECRET`. Entrambi i valori si configurano nell'ambiente di hosting e non vanno committati.

Dopo la creazione dell'amministratore, l'accesso iniziale è disabilitato. L'amministratore crea gli utenti, genera un codice di associazione e lo fa inserire o scansionare dall'app. Le credenziali degli operatori non vengono mostrate di nuovo dopo la creazione.

## Sviluppo

Requisiti: Node.js 22.13 o successivo.

```sh
npm install
npm run db:generate
npm run build
```

Il database usa Cloudflare D1 con lo schema e le migrazioni nella cartella `drizzle/`. Per il deploy, conservare il database e i segreti nell'ambiente di hosting, mai nel repository.

## Limiti della versione alfa

La scansione QR cerca il codice letto nell'anagrafica; la lettura automatica dei contatori direttamente dalle AWP/VLT non è ancora implementata. La stampa usa il dialogo di stampa del browser e richiede una stampante supportata dal telefono. Non è un'app Android nativa distribuita via Play Store.

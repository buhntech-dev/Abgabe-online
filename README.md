# Abgabe-online

Digitale Lernplattform mit Klassenräumen, Beitrittscodes, Aufgaben, Dateiablage, Chat und WebRTC-Live-Unterricht.

## Lokale Entwicklung

- Node.js 20+
- `npm install`
- `OWNER_EMAIL` und `OWNER_PASSWORD` setzen
- `npm start`

## Railway

Die App nutzt `PORT`, `JWT_SECRET` und einen S3-kompatiblen Bucket für dauerhafte Speicherung. Setze `S3_ENDPOINT`, `S3_BUCKET`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY` und `S3_REGION`. Ohne Bucket wird nur ein temporärer lokaler Fallback verwendet; Uploads sind dann deaktiviert.

Live-Calls nutzen WebRTC/STUN. Für zuverlässige Verbindungen hinter restriktiven Firewalls ist zusätzlich ein TURN-Server erforderlich.

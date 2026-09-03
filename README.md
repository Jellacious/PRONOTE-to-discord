# 🤖 PRONOTE to Discord

Un bot Discord basé sur [pronotepy](https://github.com/bain3/pronotepy) pour recevoir ses alertes PRONOTE (cours modifiés/annulés, nouvelles notes, devoirs, absences) et consulter son emploi du temps à la demande directement en **Messages Privés**.

---

## ✨ Fonctionnalités

- **🔒 100% Privé** :
  - Le bot répond **exclusivement à son propriétaire** et fonctionne **uniquement en Messages Privés (MP)**.
- **⚡ Authentification simple (`!login`)** :
  - Connexion directe via le JSON du QR Code Pronote et le PIN depuis Discord.
- **📋 Commandes à la demande** :
  - `!edt [demain|JJ/MM]` : Emploi du temps stylisé avec contenu de cours et salles.
  - `!devoirs [jours]` : Liste des devoirs avec statuts (fait / à faire).
  - `!notes` : Dernières notes reçues et moyennes.
  - `!absences` : Historique des retards et absences.
  - `!menu` : Menus du restaurant scolaire.
  - `!recap` : Déclenche le récapitulatif complet du matin.
- **🔄 Surveillance Automatique (Autocheck)** :
  - Boucle en arrière-plan toutes les XX minutes pour notifier dès qu'un changement survient (nouvelle note, cours déplacé ou annulé, devoir ajouté).
  - Récapitulatif envoyé automatiquement chaque jour à l'heure configurée.

---

## 🚀 Installation & Démarrage

### 1. Cloner et installer les dépendances

```bash
git clone <url_du_depot>
cd pronote-to-discord

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Créer l'application Discord

1. Rendez-vous sur le [Discord Developer Portal](https://discord.com/developers/applications) et cliquez sur **New Application** (ex: *PRONOTE Assistant*).
2. Dans l'onglet **Bot** :
   - Cliquez sur **Reset Token** et copiez votre `DISCORD_TOKEN`.
   - Dans la section **Privileged Gateway Intents**, activez **MESSAGE CONTENT INTENT**.
3. Dans l'onglet **OAuth2 > URL Generator** :
   - Cochez les scopes : `bot` (ou `bot` + `applications.commands`)
   - Cochez les permissions : `Send Messages`, `Embed Links`, `Read Message History`, `Manage Messages`
   - Ouvrez l'URL générée dans votre navigateur pour autoriser le bot et pouvoir lui envoyer un message privé.

### 3. Configuration automatique

Lancez l'assistant interactif :
```bash
python3 setup.py
```
Le script vous demandera votre token Discord, détectera automatiquement votre compte propriétaire et vous guidera pour lier Pronote si vous le souhaitez.

---

## 🔑 Connexion à Pronote

Deux méthodes au choix :

### Méthode 1 : Directement depuis Discord
1. Envoyez `!login` en message privé à votre bot.
2. Le bot vous fournit un code PIN temporaire.
3. Sur Pronote Web : cliquez sur l'icône **QR Code** (à côté de votre prénom).
4. Saisissez le code PIN et copiez le JSON affiché.
5. Collez le JSON directement dans le chat Discord.

### Méthode 2 : Pendant le `setup.py`
L'assistant de configuration vous propose de générer le code PIN et de coller le JSON directement dans votre terminal.

---

## 📖 Liste des Commandes

| Commande | Description |
|---|---|
| `!login` | Connexion interactive au compte Pronote |
| `!logout` | Déconnexion et suppression des identifiants |
| `!status` | État de la connexion Pronote et de l'autocheck |
| `!edt [demain\|JJ/MM]` | Affiche l'emploi du temps |
| `!devoirs [jours]` | Affiche les devoirs (7 jours par défaut) |
| `!notes` | Affiche les dernières notes et la moyenne générale |
| `!absences` | Affiche les absences et retards |
| `!menu [demain]` | Affiche le menu du restaurant scolaire |
| `!recap` | Envoie le récapitulatif complet |
| `!autocheck on / off` | Active ou désactive la surveillance automatique |
| `!autocheck interval <min>` | Modifie l'intervalle entre chaque scan (minimum : 15 min) |
| `!autocheck now` | Force une vérification immédiate |
| `!help` | Affiche l'aide des commandes |

Developed with ❤️ by [Jellacious](https://github.com/jellacious).
Note : AI was used in this project.
#!/usr/bin/env python3
"""
Assistant de configuration interactive pour Pronote Discord Bot.
"""

import os
import sys
import json
import re
import secrets
import urllib.request
import urllib.error
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
CONFIG_FILE = SCRIPT_DIR / "config.py"
CREDENTIALS_FILE = SCRIPT_DIR / "credentials.json"

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def banner():
    print("=" * 60)
    print("       CONFIGURATION DU BOT DISCORD PRONOTE")
    print("=" * 60)
    print()

def fetch_owner_info_from_token(token: str):
    """Interroge l'API Discord pour valider le token et trouver le propriétaire."""
    url = "https://discord.com/api/v10/oauth2/applications/@me"
    headers = {
        "Authorization": f"Bot {token}",
        "User-Agent": "PronoteDiscordBot (https://github.com, 1.0)"
    }
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode("utf-8"))
            owner = data.get("owner")
            bot_name = data.get("name", "Bot")
            
            if owner:
                owner_id = int(owner["id"])
                owner_name = owner.get("username", "Inconnu")
                return True, bot_name, owner_id, owner_name
            else:
                team = data.get("team")
                if team and team.get("owner_user_id"):
                    owner_id = int(team["owner_user_id"])
                    return True, bot_name, owner_id, "Team Owner"
                return False, bot_name, None, "Impossible de déterminer le propriétaire de l'application."
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return False, None, None, "Token Discord invalide (401 Unauthorized)."
        return False, None, None, f"Erreur API Discord ({e.code}) : {e.reason}"
    except Exception as e:
        return False, None, None, f"Erreur de connexion : {e}"

def ask_token():
    print("1. Token de votre bot Discord")
    print("   (Disponible sur https://discord.com/developers/applications > Bot > Reset Token)\n")
    while True:
        token = input("DISCORD_TOKEN : ").strip()
        if not token:
            print("Le token ne peut pas être vide.\n")
            continue

        print("\nVérification du token...")
        success, bot_name, owner_id, owner_name = fetch_owner_info_from_token(token)

        if not success:
            print(f"Erreur : {owner_name}")
            print("Veuillez vérifier et ressaisir votre token.\n")
            continue

        print(f"Application detectee : {bot_name}")
        print(f"Compte proprietaire detecte : {owner_name} (ID: {owner_id})")
        
        while True:
            confirm = input("\nEst-ce bien votre compte ? (o/n) : ").strip().lower()
            if confirm in ["o", "oui", "y", "yes"]:
                break
            elif confirm in ["n", "non", "no"]:
                manual_id = input("Entrez manuellement votre OWNER_ID Discord : ").strip()
                try:
                    owner_id = int(manual_id)
                except ValueError:
                    print("ID invalide, conservation de l'ID détecté.")
                break
            else:
                print("Veuillez répondre par 'o' pour oui ou 'n' pour non.")

        return token, owner_id, bot_name, owner_name

def setup_pronote_login():
    """Permet de connecter Pronote directement pendant le setup."""
    pin_auto = f"{secrets.randbelow(9000) + 1000}"
    print("\n--- Connexion Pronote ---")
    print("1. Sur Pronote Web : À côté de votre prénom, cliquez sur le logo QR Code.")
    print(f"2. Dans 'Code de vérification à 4 chiffres', saisissez : {pin_auto}")
    print("3. Scannez ou copiez le JSON du QR Code.")
    print("   (Attention : ce code et ce JSON sont strictement confidentiels, ne les partagez jamais).")
    
    qr_input = input("\nCollez le JSON du QR Code : ").strip()
    if not qr_input:
        print("Connexion Pronote ignorée. Vous pourrez le faire sur Discord avec !login.")
        return

    print("Connexion à Pronote en cours...")
    try:
        import pronotepy
        import pronotepy.clients
        from pronotepy.clients import _enleverAlea, _Encryption, CryptoError, SHA256

        # Appliquer le patch 2026
        def _patched_login(self) -> bool:
            if self.ent:
                username = self.attributes["e"]
                password = self.attributes["f"]
            else:
                username = self.username
                password = self.password

            ident_json = {
                "genreConnexion": 0,
                "genreEspace": int(self.attributes["a"]),
                "identifiant": username,
                "pourENT": True if self.ent else False,
                "enConnexionAuto": False,
                "demandeConnexionAuto": False,
                "demandeConnexionAppliMobile": self.login_mode == "qr_code",
                "demandeConnexionAppliMobileJeton": self.login_mode == "qr_code",
                "enConnexionAppliMobile": self.login_mode == "token",
                "uuidAppliMobile": (self.uuid if self.login_mode in ("qr_code", "token") else ""),
                "loginTokenSAV": "",
            }
            idr = self.post("Identification", data=ident_json)
            challenge = idr["dataSec"]["data"]["challenge"]
            e = _Encryption()
            e.aes_set_iv(self.communication.encryption.aes_iv)

            if self.ent:
                motdepasse = SHA256.new(str(password).encode()).hexdigest().upper()
                e.aes_set_key(motdepasse.encode())
            else:
                if idr["dataSec"]["data"]["modeCompLog"]:
                    username = username.lower()
                if idr["dataSec"]["data"]["modeCompMdp"]:
                    password = password.lower()
                alea = idr["dataSec"]["data"].get("alea", "")
                motdepasse = SHA256.new((alea + password).encode()).hexdigest().upper()
                e.aes_set_key((username + motdepasse).encode())

            try:
                dec = e.aes_decrypt(bytes.fromhex(challenge))
                dec_no_alea = _enleverAlea(dec.decode())
                ch = e.aes_encrypt(dec_no_alea.encode()).hex()
            except (CryptoError, UnicodeDecodeError, ValueError):
                ch = e.aes_encrypt(challenge.encode()).hex()

            auth_json = {"connexion": 0, "challenge": ch, "espace": int(self.attributes["a"])}
            auth_response = self.post("Authentification", data=auth_json)
            if "cle" in auth_response["dataSec"]["data"]:
                self.communication.after_auth(auth_response, e.aes_key)
                self.encryption.aes_key = e.aes_key
                actionsDoubleAuth = auth_response["dataSec"]["data"].get("actionsDoubleAuth")
                if actionsDoubleAuth:
                    actions = json.loads(actionsDoubleAuth["V"])
                    doRegisterDevice = 5 in actions or 3 in actions
                    doVerifyPin = 3 in actions
                    self._do_2fa(doVerifyPin, doRegisterDevice, self.account_pin, self.device_name)

                last_conn = auth_response["dataSec"]["data"].get("derniereConnexion")
                self.last_connection = (pronotepy.dataClasses.Util.datetime_parse(last_conn["V"]) if last_conn else None)
                if self.login_mode in ("qr_code", "token") and auth_response["dataSec"]["data"].get("jetonConnexionAppliMobile"):
                    self.password = auth_response["dataSec"]["data"]["jetonConnexionAppliMobile"]
                self.parametres_utilisateur = self.post("ParametresUtilisateur")
                self.info = pronotepy.dataClasses.ClientInfo(self, self.parametres_utilisateur["dataSec"]["data"]["ressource"])
                self.communication.authorized_onglets = pronotepy.clients._prepare_onglets(self.parametres_utilisateur["dataSec"]["data"]["listeOnglets"])
                return True
            return False

        pronotepy.clients.ClientBase._login = _patched_login

        qr_dict = json.loads(qr_input)
        url = qr_dict.get("url", "")
        if url.endswith("parent.html"):
            client_class = pronotepy.ParentClient
        elif url.endswith("viescolaire.html"):
            client_class = pronotepy.VieScolaireClient
        else:
            client_class = pronotepy.Client

        uuid_device = secrets.token_hex(8)
        client = client_class.qrcode_login(qr_dict, pin_auto, uuid_device)

        if client.logged_in:
            CREDENTIALS_FILE.write_text(json.dumps(client.export_credentials(), indent=2), encoding="utf-8")
            name = client.info.name if client.info else "Utilisateur"
            print(f"Connexion Pronote réussie pour {name} !")
        else:
            print("Échec de la connexion Pronote. Vous pourrez réessayer sur Discord avec !login.")
    except Exception as e:
        print(f"Erreur lors de la connexion Pronote : {e}")
        print("Vous pourrez lier votre compte sur Discord avec !login.")

def ask_configuration():
    print("\n" + "-" * 60)
    print("Souhaitez-vous tout configurer ici dès maintenant, ou plus tard via les commandes du bot ?")
    configure_now = input("Configurer ici ? (o/N, défaut: Non, via les commandes) : ").strip().lower()
    
    # Valeurs par défaut
    autocheck = True
    interval = 15
    morning_recap = "07:00"
    morning_recap_weekend = False

    if configure_now not in ["o", "oui", "y", "yes"]:
        return autocheck, interval, morning_recap, morning_recap_weekend, False

    print("\n--- Configuration des options ---")

    # 1. Autocheck (surveillance continue)
    autocheck_input = input("Activer la surveillance automatique des changements ? (O/n, défaut: Oui) : ").strip().lower()
    autocheck = False if autocheck_input in ["n", "non", "no", "false"] else True

    # 2. Intervalle (uniquement si surveillance activée)
    if autocheck:
        while True:
            interval_input = input("Intervalle entre les vérifications en minutes (minimum: 15, défaut: 15) : ").strip()
            if not interval_input:
                interval = 15
                break
            try:
                val = int(interval_input)
                if val < 15:
                    print("L'intervalle minimum est de 15 minutes pour éviter d'être bloqué par Pronote.")
                    interval = 15
                else:
                    interval = val
                break
            except ValueError:
                print("Veuillez entrer un nombre entier valide.")

    # 3. Récapitulatif matinal
    morning_enable = input("Recevoir automatiquement le récapitulatif chaque matin ? (O/n, défaut: Oui) : ").strip().lower()
    if morning_enable in ["n", "non", "no", "false"]:
        morning_recap = "off"
        morning_recap_weekend = False
    else:
        while True:
            recap_input = input("Heure d'envoi du récapitulatif matinal (HH:MM, défaut: 07:00) : ").strip()
            if not recap_input:
                morning_recap = "07:00"
                break
            
            match = re.match(r"^([01]?[0-9]|2[0-3]):([0-5][0-9])$", recap_input)
            if match:
                h, m = int(match.group(1)), int(match.group(2))
                morning_recap = f"{h:02d}:{m:02d}"
                break
            else:
                print("Format invalide. Veuillez entrer une heure au format HH:MM (ex: 07:00, 08:30).")

        recap_weekend_input = input("Recevoir aussi le récapitulatif le week-end (samedi/dimanche) ? (o/N, défaut: Non) : ").strip().lower()
        morning_recap_weekend = True if recap_weekend_input in ["o", "oui", "y", "yes", "true"] else False

    # 4. Connexion Pronote immédiate
    want_login = input("\nSouhaitez-vous vous connecter à votre compte Pronote dès maintenant ? (O/n, défaut: Oui) : ").strip().lower()
    do_pronote_login = False if want_login in ["n", "non", "no", "false"] else True

    return autocheck, interval, morning_recap, morning_recap_weekend, do_pronote_login

def main():
    clear_screen()
    banner()

    if CONFIG_FILE.exists():
        print("Un fichier 'config.py' existe déjà.")
        overwrite = input("Voulez-vous le réécrire ? (o/N) : ").strip().lower()
        if overwrite not in ["o", "oui", "y", "yes"]:
            print("\nConfiguration annulée. config.py reste inchangé.")
            sys.exit(0)
        print()

    token, owner_id, bot_name, owner_name = ask_token()
    autocheck, interval, morning_recap, morning_recap_weekend, do_login = ask_configuration()

    if do_login:
        setup_pronote_login()

    config_content = f"""# --- Configuration du Bot Discord Pronote ---
# Fichier généré automatiquement par setup.py

# Token secret du bot Discord
DISCORD_TOKEN = "{token}"

# Identifiant Discord du propriétaire ({owner_name})
OWNER_ID = {owner_id}

# Configuration de la surveillance automatique (Autocheck)
AUTOCHECK_ENABLED = {autocheck}
AUTOCHECK_INTERVAL_MINUTES = {interval}
MORNING_RECAP_TIME = "{morning_recap}"
MORNING_RECAP_WEEKEND = {morning_recap_weekend}
"""

    CONFIG_FILE.write_text(config_content, encoding="utf-8")

    print("\n" + "=" * 60)
    print("Configuration terminée avec succès !")
    print("=" * 60)
    
    launch_now = input("\nSouhaitez-vous lancer le bot afin de le tester dès maintenant ? (O/n, défaut: Oui) : ").strip().lower()
    if launch_now not in ["n", "non", "no", "false"]:
        print("\nLancement du bot...\n" + "=" * 60)
        try:
            import subprocess
            subprocess.run([sys.executable, str(SCRIPT_DIR / "main.py")])
        except KeyboardInterrupt:
            print("\nArrêt du bot.")
    else:
        print("\nPour lancer le bot plus tard :")
        print("   python3 main.py\n")

if __name__ == "__main__":
    main()

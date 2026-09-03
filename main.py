import discord
from discord.ext import commands, tasks
import pronotepy
import pronotepy.clients
from pronotepy.clients import _enleverAlea, _Encryption, CryptoError, SHA256
import json
import datetime
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import asyncio

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
        "uuidAppliMobile": (
            self.uuid if self.login_mode in ("qr_code", "token") else ""
        ),
        "loginTokenSAV": "",
    }
    idr = self.post("Identification", data=ident_json)
    pronotepy.clients.log.debug("identification")

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

    auth_json = {
        "connexion": 0,
        "challenge": ch,
        "espace": int(self.attributes["a"]),
    }
    auth_response = self.post("Authentification", data=auth_json)
    if "cle" in auth_response["dataSec"]["data"]:
        self.communication.after_auth(auth_response, e.aes_key)
        self.encryption.aes_key = e.aes_key

        actionsDoubleAuth = auth_response["dataSec"]["data"].get("actionsDoubleAuth")
        if actionsDoubleAuth:
            actions = json.loads(actionsDoubleAuth["V"])
            doRegisterDevice = 5 in actions or 3 in actions
            doVerifyPin = 3 in actions
            self._do_2fa(
                doVerifyPin,
                doRegisterDevice,
                self.account_pin,
                self.device_name,
            )

        pronotepy.clients.log.info(f"successfully logged in as {self.username}")

        last_conn = auth_response["dataSec"]["data"].get("derniereConnexion")
        self.last_connection = (
            pronotepy.dataClasses.Util.datetime_parse(last_conn["V"]) if last_conn else None
        )

        if self.login_mode in ("qr_code", "token") and auth_response["dataSec"]["data"].get("jetonConnexionAppliMobile"):
            self.password = auth_response["dataSec"]["data"]["jetonConnexionAppliMobile"]

        self.parametres_utilisateur = self.post("ParametresUtilisateur")
        self.info = pronotepy.dataClasses.ClientInfo(
            self, self.parametres_utilisateur["dataSec"]["data"]["ressource"]
        )
        self.communication.authorized_onglets = pronotepy.clients._prepare_onglets(
            self.parametres_utilisateur["dataSec"]["data"]["listeOnglets"]
        )
        pronotepy.clients.log.info("got onglets data.")
        return True
    else:
        pronotepy.clients.log.info("login failed")
        return False

pronotepy.clients.ClientBase._login = _patched_login


# ─── Chargement de la Configuration ───────────────────────────
SCRIPT_DIR = Path(__file__).parent
CONFIG_FILE = SCRIPT_DIR / "config.py"

if not CONFIG_FILE.exists():
    print("Fichier config.py manquant ! Veuillez lancer 'python3 setup.py' pour initialiser le bot.")
    exit(1)

import config

DISCORD_TOKEN = getattr(config, "DISCORD_TOKEN", "")
OWNER_ID = int(getattr(config, "OWNER_ID", 0))
AUTOCHECK_ENABLED = getattr(config, "AUTOCHECK_ENABLED", True)
AUTOCHECK_INTERVAL_MINUTES = getattr(config, "AUTOCHECK_INTERVAL_MINUTES", 15)
MORNING_RECAP_TIME = getattr(config, "MORNING_RECAP_TIME", "07:00")

STATE_FILE = SCRIPT_DIR / "state.json"
CREDENTIALS_FILE = SCRIPT_DIR / "credentials.json"
LOG_FILE = SCRIPT_DIR / "logs.txt"

# ─── Configuration des Logs ───────────────────────────────────
logger = logging.getLogger("pronote_discord_bot")
logger.setLevel(logging.INFO)

console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("[%(asctime)s] %(message)s", datefmt="%d/%m/%Y %H:%M:%S"))

file_handler = RotatingFileHandler(
    LOG_FILE,
    maxBytes=2 * 1024 * 1024,
    backupCount=3,
    encoding="utf-8"
)
file_handler.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", datefmt="%d/%m/%Y %H:%M:%S"))

logger.handlers.clear()
logger.addHandler(console_handler)
logger.addHandler(file_handler)

# ─── Initialisation du Bot Discord ─────────────────────────────
intents = discord.Intents.default()
intents.message_content = True
intents.dm_messages = True

bot = commands.Bot(command_prefix="!", intents=intents, help_command=None)

# ─── Helpers d'État et de Données ─────────────────────────────
def load_state() -> dict:
    """Charge l'état précédent depuis state.json."""
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except Exception as e:
            logger.warning(f"⚠️ Impossible de lire state.json ({e}), initialisation par défaut.")
    return {
        "daily_done_date": None,
        "edt": {},
        "grades": [],
        "homework": {},
        "absences": []
    }

def save_state(state: dict):
    """Sauvegarde l'état courant dans state.json."""
    STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")

def lesson_to_dict(lesson) -> dict:
    return {
        "start": lesson.start.strftime("%H:%M"),
        "end": lesson.end.strftime("%H:%M") if hasattr(lesson, "end") and lesson.end else "",
        "subject": lesson.subject.name if lesson.subject else "Autre / Étude",
        "classroom": lesson.classroom or "",
        "canceled": lesson.canceled or False,
        "teacher": lesson.teacher_name or ""
    }

def format_lesson_line(l: dict) -> str:
    status_icon = "❌" if l["canceled"] else "🔹"
    annule = " **[ANNULÉ]**" if l["canceled"] else ""
    salle = f" • Salle `{l['classroom']}`" if l["classroom"] else ""
    prof = f" ({l['teacher']})" if l["teacher"] else ""
    return f"{status_icon} **{l['start']}** - {l['subject']}{prof}{salle}{annule}"

def hw_to_dict(hw) -> dict:
    return {
        "date": hw.date.isoformat(),
        "subject": hw.subject.name if hw.subject else "Devoir",
        "description": hw.description.strip() if hw.description else "",
        "done": hw.done or False
    }

def hw_id(hw: dict) -> str:
    return f"{hw['date']}-{hw['subject']}-{hw['description'][:30]}"

def get_end_of_week_plus_monday(today: datetime.date) -> datetime.date:
    days_until_friday = 4 - today.weekday()
    if days_until_friday < 0:
        days_until_friday += 7
    friday = today + datetime.timedelta(days=days_until_friday)
    monday_next = friday + datetime.timedelta(days=3)
    return monday_next

# ─── Gestionnaire de Connexion Pronote ──────────────────────────
class PronoteSession:
    def __init__(self):
        self._client: pronotepy.Client | None = None

    def is_connected(self) -> bool:
        return self._client is not None and self._client.logged_in

    def get_client(self) -> pronotepy.Client | None:
        """Récupère ou reconnecte le client Pronote."""
        if not CREDENTIALS_FILE.exists():
            return None

        try:
            credentials = json.loads(CREDENTIALS_FILE.read_text(encoding="utf-8"))
            client = pronotepy.Client.token_login(**credentials)
            if client.logged_in:
                # Sauvegarde du nouveau jeton renouvelé
                CREDENTIALS_FILE.write_text(json.dumps(client.export_credentials(), indent=2), encoding="utf-8")
                self._client = client
                return client
            return None
        except Exception as e:
            logger.error(f"Erreur lors de la connexion via token Pronote : {e}")
            return None

    def login_with_qrcode(self, qr_data: dict | str, pin: str) -> tuple[bool, str]:
        """Authentifie avec les données du QR Code et le code PIN."""
        import secrets
        try:
            if isinstance(qr_data, str):
                qr_dict = json.loads(qr_data)
            else:
                qr_dict = qr_data

            url = qr_dict.get("url", "")
            if url.endswith("parent.html"):
                client_class = pronotepy.ParentClient
            elif url.endswith("viescolaire.html"):
                client_class = pronotepy.VieScolaireClient
            else:
                client_class = pronotepy.Client

            uuid_device = secrets.token_hex(8)
            client = client_class.qrcode_login(qr_dict, pin, uuid_device)

            if client.logged_in:
                CREDENTIALS_FILE.write_text(json.dumps(client.export_credentials(), indent=2), encoding="utf-8")
                self._client = client
                name = client.info.name if client.info else "Utilisateur"
                logger.info(f"Connexion QR code réussie pour {name}")
                return True, f"Connecté avec succès en tant que **{name}** !"
            else:
                return False, "Échec de l'authentification QR code (logged_in = False)."
        except json.JSONDecodeError:
            return False, "Le JSON du QR code est invalide. Vérifiez que vous avez bien copié tout le bloc JSON."
        except Exception as e:
            logger.error(f"Erreur login QR code : {e}")
            return False, f"Erreur lors de la connexion : {e}"

    def logout(self):
        """Supprime les identifiants locaux."""
        self._client = None
        if CREDENTIALS_FILE.exists():
            CREDENTIALS_FILE.unlink()
        logger.info("Deconnexion Pronote effectuee.")

pronote = PronoteSession()

# ─── Filtrage Global de Sécurité : Owner Only & DMs Only ───────
@bot.check
async def check_owner_and_dm(ctx: commands.Context) -> bool:
    """Refuse tout message qui n'est pas un MP avec le propriétaire."""
    is_owner = (ctx.author.id == OWNER_ID)
    is_dm = isinstance(ctx.channel, discord.DMChannel)
    return is_owner and is_dm

@bot.event
async def on_command_error(ctx: commands.Context, error: Exception):
    if isinstance(error, commands.CheckFailure):
        # Ignore silencieusement les messages non autorisés
        return
    elif isinstance(error, commands.CommandNotFound):
        # Ignore silencieusement les commandes inexistantes
        return
    elif isinstance(error, commands.CommandOnCooldown):
        await ctx.send(f"⏳ Doucement ! Vous pourrez réutiliser cette commande dans `{round(error.retry_after, 1)}s`.")
    elif isinstance(error, commands.MissingRequiredArgument):
        await ctx.send(f"⚠️ Argument manquant. Utilisez `!help` pour voir l'utilisation correcte.")
    else:
        logger.error(f"Erreur commande '{ctx.command}': {error}")
        await ctx.send(f"❌ Une erreur s'est produite : `{error}`")

# ─── Génération des Embeds de Récap / Alertes ──────────────────
def build_edt_embed(client: pronotepy.Client, target_date: datetime.date, title_prefix: str = "📅 Emploi du temps") -> discord.Embed:
    day_str = target_date.strftime("%A %d %B %Y").capitalize()
    embed = discord.Embed(
        title=f"{title_prefix} — {day_str}",
        color=discord.Color.blurple(),
        timestamp=datetime.datetime.now()
    )
    try:
        lessons = client.lessons(target_date)
        lessons = sorted(lessons, key=lambda l: l.start)
        if not lessons:
            embed.description = "🎉 Aucun cours prévu pour cette journée !"
            return embed

        desc_lines = []
        for l in lessons:
            ld = lesson_to_dict(l)
            desc_lines.append(format_lesson_line(ld))
            # Contenu de séance si disponible
            if hasattr(l, "content") and l.content:
                c = l.content
                if c.title:
                    desc_lines.append(f"  └ 📖 *{c.title}*")
                if c.description:
                    d_clean = c.description.strip()
                    if d_clean:
                        desc_lines.append(f"    *{d_clean[:120]}...*" if len(d_clean) > 120 else f"    *{d_clean}*")

        embed.description = "\n".join(desc_lines)
    except Exception as e:
        embed.description = f"⚠️ Impossible de récupérer l'emploi du temps : {e}"
        embed.color = discord.Color.red()
    return embed

def build_homework_embed(client: pronotepy.Client, max_days: int = 7) -> discord.Embed:
    today = datetime.date.today()
    limit = today + datetime.timedelta(days=max_days)
    embed = discord.Embed(
        title=f"📚 Devoirs à faire (jusqu'au {limit.strftime('%d/%m')})",
        color=discord.Color.blue(),
        timestamp=datetime.datetime.now()
    )
    try:
        hws = client.homework(today, limit)
        if not hws:
            embed.description = "🎉 Aucun devoir à faire ! Tout est à jour."
            return embed

        hws = sorted(hws, key=lambda h: h.date)
        by_date: dict[datetime.date, list] = {}
        for hw in hws:
            by_date.setdefault(hw.date, []).append(hw)

        for d, list_hw in by_date.items():
            field_name = f"🗓️ {d.strftime('%A %d/%m').capitalize()}"
            lines = []
            for hw in list_hw:
                status = "✅" if hw.done else "❌"
                sub = hw.subject.name if hw.subject else "Devoir"
                desc = hw.description.strip() if hw.description else "Pas de consigne"
                lines.append(f"{status} **{sub}** : {desc}")
            embed.add_field(name=field_name, value="\n".join(lines), inline=False)
    except Exception as e:
        embed.description = f"⚠️ Erreur lors de la récupération des devoirs : {e}"
        embed.color = discord.Color.red()
    return embed

def build_menu_embed(client: pronotepy.Client, target_date: datetime.date) -> discord.Embed:
    embed = discord.Embed(
        title=f"🍽️ Menu de la cantine — {target_date.strftime('%d/%m/%Y')}",
        color=discord.Color.gold(),
        timestamp=datetime.datetime.now()
    )
    try:
        menus = client.menus(target_date, target_date)
        if not menus:
            embed.description = "Aucun menu disponible pour cette date."
            return embed

        for i, menu in enumerate(menus):
            moment = "☀️ Midi" if i == 0 else "🌙 Soir"
            courses = [
                ("Entrée", menu.first_meal),
                ("Plat principal", menu.main_meal),
                ("Accompagnement", menu.side_meal),
                ("Fromage", menu.cheese),
                ("Dessert", menu.dessert),
                ("Autre", menu.other_meal),
            ]
            menu_text = []
            for label, meal_list in courses:
                if meal_list:
                    plats = ", ".join(food.name for food in meal_list)
                    menu_text.append(f"• **{label}** : {plats}")
            embed.add_field(name=moment, value="\n".join(menu_text) if menu_text else "Menu non renseigné", inline=False)
    except Exception as e:
        embed.description = f"⚠️ Impossible de récupérer les menus : {e}"
        embed.color = discord.Color.red()
    return embed

# ─── Logique de Détection (Autocheck) ───────────
async def run_autocheck_cycle(send_notifications: bool = True) -> list[discord.Embed]:
    """Exécute un cycle de vérification et retourne la liste des embeds à envoyer."""
    client = pronote.get_client()
    if not client:
        return []

    state = load_state()
    today = datetime.date.today()
    alerts: list[discord.Embed] = []

    # 1. Surveillance Emploi du Temps (sur 14 jours)
    new_edt = {}
    edt_embeds = []
    for i in range(14):
        day = today + datetime.timedelta(days=i)
        day_key = day.isoformat()
        try:
            lessons = client.lessons(day)
            new_edt[day_key] = [lesson_to_dict(l) for l in sorted(lessons, key=lambda l: l.start)]
        except Exception:
            new_edt[day_key] = []

        old_lessons = state.get("edt", {}).get(day_key)
        new_lessons = new_edt[day_key]

        if old_lessons is not None and old_lessons != new_lessons:
            day_formatted = day.strftime("%A %d %B").capitalize()
            embed = discord.Embed(
                title=f"🔄 Modification EDT — {day_formatted}",
                color=discord.Color.orange(),
                timestamp=datetime.datetime.now()
            )
            old_by_time = {l["start"]: l for l in old_lessons}
            new_by_time = {l["start"]: l for l in new_lessons}
            all_times = sorted(set(list(old_by_time.keys()) + list(new_by_time.keys())))

            changes = []
            for t in all_times:
                o = old_by_time.get(t)
                n = new_by_time.get(t)
                if o and n and o != n:
                    if not o["canceled"] and n["canceled"]:
                        changes.append(f"❌ **Cours annulé** : {n['subject']} à {t}")
                    elif o["classroom"] != n["classroom"]:
                        changes.append(f"🏫 **Changement de salle** ({n['subject']} à {t}) : `{o['classroom'] or '?'}` ➔ `{n['classroom']}`")
                    else:
                        changes.append(f"✏️ **Modifié** ({t}) : {n['subject']}")
                elif o and not n:
                    changes.append(f"🗑️ **Cours supprimé** : {o['subject']} ({t})")
                elif n and not o:
                    changes.append(f"➕ **Nouveau cours ajouté** : {n['subject']} ({t}) en `{n['classroom']}`")

            if changes:
                embed.description = "\n".join(changes)
                edt_embeds.append(embed)

    state["edt"] = new_edt
    alerts.extend(edt_embeds)

    # 2. Surveillance Nouvelles Notes
    seen_grades = set(state.get("grades", []))
    new_seen_grades = set(seen_grades)
    grade_alerts = []

    try:
        for period in client.periods:
            for grade in period.grades:
                grade_id = f"{grade.subject.name}-{grade.date}-{grade.grade}"
                if grade_id not in new_seen_grades:
                    new_seen_grades.add(grade_id)
                    embed = discord.Embed(
                        title=f"📝 Nouvelle note reçue !",
                        color=discord.Color.green(),
                        timestamp=datetime.datetime.now()
                    )
                    embed.add_field(name="Matière", value=grade.subject.name, inline=True)
                    embed.add_field(name="Note", value=f"**{grade.grade}** / {grade.out_of}", inline=True)
                    if grade.average:
                        embed.add_field(name="Moyenne de classe", value=f"{grade.average}/{grade.out_of}", inline=True)
                    if grade.max:
                        embed.add_field(name="Max / Min", value=f"Max: {grade.max} | Min: {grade.min}", inline=True)
                    if grade.comment:
                        embed.add_field(name="Commentaire", value=grade.comment, inline=False)
                    grade_alerts.append(embed)
        state["grades"] = list(new_seen_grades)
        alerts.extend(grade_alerts)
    except Exception as e:
        logger.warning(f"Erreur check notes : {e}")

    # 3. Surveillance Nouvelles Absences
    seen_absences = set(state.get("absences", []))
    new_seen_absences = set(seen_absences)
    abs_alerts = []

    try:
        for period in client.periods:
            for absence in period.absences:
                abs_id = f"{absence.from_date.isoformat()}-{absence.to_date.isoformat()}"
                if abs_id not in new_seen_absences:
                    new_seen_absences.add(abs_id)
                    justified = "✅ Justifiée" if absence.justified else "❌ Non justifiée"
                    embed = discord.Embed(
                        title="🚨 Nouvelle absence signalée",
                        color=discord.Color.red() if not absence.justified else discord.Color.dark_orange(),
                        timestamp=datetime.datetime.now()
                    )
                    date_from = absence.from_date.strftime("%d/%m %H:%M")
                    date_to = absence.to_date.strftime("%d/%m %H:%M")
                    embed.add_field(name="Période", value=f"Du {date_from} au {date_to} ({absence.hours}h)", inline=False)
                    embed.add_field(name="Statut", value=justified, inline=True)
                    if absence.reasons:
                        reasons_list = [r.name if hasattr(r, "name") else str(r) for r in absence.reasons]
                        embed.add_field(name="Motif", value=", ".join(reasons_list), inline=True)
                    abs_alerts.append(embed)
        state["absences"] = list(new_seen_absences)
        alerts.extend(abs_alerts)
    except Exception as e:
        logger.warning(f"Erreur check absences : {e}")

    # 4. Surveillance Nouveaux Devoirs
    try:
        deadline = get_end_of_week_plus_monday(today)
        homeworks = client.homework(today, deadline)
        old_homework = state.get("homework", {})
        new_homework = {}
        hw_alerts = []

        for hw in homeworks:
            d = hw_to_dict(hw)
            hid = hw_id(d)
            new_homework[hid] = d

            if hid not in old_homework:
                embed = discord.Embed(
                    title="📚 Nouveau devoir ajouté",
                    color=discord.Color.blue(),
                    timestamp=datetime.datetime.now()
                )
                embed.add_field(name="Pour le", value=f"🗓️ {d['date'][5:].replace('-', '/')}", inline=True)
                embed.add_field(name="Matière", value=d["subject"], inline=True)
                embed.add_field(name="Consigne", value=d["description"] or "Pas de description", inline=False)
                hw_alerts.append(embed)
            else:
                old = old_homework[hid]
                if old["description"] != d["description"]:
                    embed = discord.Embed(
                        title=f"📚 Devoir modifié : {d['subject']}",
                        color=discord.Color.gold(),
                        timestamp=datetime.datetime.now()
                    )
                    embed.add_field(name="Pour le", value=f"🗓️ {d['date'][5:].replace('-', '/')}", inline=False)
                    embed.add_field(name="Avant", value=old["description"] or "Vide", inline=False)
                    embed.add_field(name="Après", value=d["description"] or "Vide", inline=False)
                    hw_alerts.append(embed)

        state["homework"] = new_homework
        alerts.extend(hw_alerts)
    except Exception as e:
        logger.warning(f"Erreur check devoirs : {e}")

    save_state(state)
    return alerts

# ─── Tâche de Fond : Autocheck Loop ────────────────────────────
@tasks.loop(minutes=AUTOCHECK_INTERVAL_MINUTES)
async def autocheck_task():
    try:
        alerts = await run_autocheck_cycle(send_notifications=True)
        if alerts:
            user = await bot.fetch_user(OWNER_ID)
            if user:
                for alert in alerts:
                    await user.send(embed=alert)
                    await asyncio.sleep(0.5)
            logger.info(f"{len(alerts)} alerte(s) envoyee(s) au proprietaire.")
        else:
            logger.info("Autocheck termine : aucun changement.")
    except Exception as e:
        logger.error(f"Erreur lors de l'autocheck loop : {e}")

# ─── Tâche de Fond : Récapitulatif du Matin ─────────────────────
@tasks.loop(minutes=1)
async def morning_recap_task():
    if not MORNING_RECAP_TIME or MORNING_RECAP_TIME.lower() == "off" or ":" not in MORNING_RECAP_TIME:
        return

    now = datetime.datetime.now()
    try:
        target_hour, target_minute = map(int, MORNING_RECAP_TIME.split(":"))
    except ValueError:
        return

    if now.hour == target_hour and now.minute == target_minute:
        state = load_state()
        today = datetime.date.today()
        if state.get("daily_done_date") == today.isoformat():
            return  # Déjà envoyé aujourd'hui

        client = pronote.get_client()
        if not client:
            return

        user = await bot.fetch_user(OWNER_ID)
        if not user:
            return

        logger.info("Envoi automatique du recapitulatif du matin...")
        
        # 1. EDT Aujourd'hui
        embed_today = build_edt_embed(client, today, title_prefix="🌅 Emploi du temps d'aujourd'hui")
        await user.send(embed=embed_today)
        
        # 2. EDT Demain
        tomorrow = today + datetime.timedelta(days=1)
        embed_tomorrow = build_edt_embed(client, tomorrow, title_prefix="📅 Emploi du temps de demain")
        await user.send(embed=embed_tomorrow)

        # 3. Devoirs
        embed_hw = build_homework_embed(client, max_days=7)
        await user.send(embed=embed_hw)

        # 4. Menus
        embed_menu = build_menu_embed(client, today)
        await user.send(embed=embed_menu)

        state["daily_done_date"] = today.isoformat()
        save_state(state)

# ─── Événement de Démarrage ────────────────────────────────────
@bot.event
async def on_ready():
    logger.info(f"Bot Discord connecte sous {bot.user.name} ({bot.user.id})")
    print(f"Pronote Discord Bot est en ligne ! Proprietaire configure : {OWNER_ID}")

    if AUTOCHECK_ENABLED and not autocheck_task.is_running():
        autocheck_task.change_interval(minutes=AUTOCHECK_INTERVAL_MINUTES)
        autocheck_task.start()
        logger.info(f"Autocheck active (toutes les {AUTOCHECK_INTERVAL_MINUTES} min).")

    if not morning_recap_task.is_running():
        morning_recap_task.start()
        logger.info(f"Tache recap du matin programmee a {MORNING_RECAP_TIME}.")

# ─── Commandes Utilisateur ─────────────────────────────────────
@bot.command(name="login")
async def cmd_login(ctx: commands.Context):
    """Lance la procédure interactive de connexion Pronote avec génération de code PIN."""
    # Suppression automatique du message pour propreté
    try:
        await ctx.message.delete()
    except Exception:
        pass

    client = pronote.get_client()
    if client and client.logged_in:
        name = client.info.name if client.info else "Utilisateur"
        embed = discord.Embed(
            title="🟢 Déjà connecté à Pronote",
            description=f"Vous êtes déjà connecté sous **{name}**.\nSi vous souhaitez changer de compte, utilisez `!logout` puis reconnectez-vous.",
            color=discord.Color.green()
        )
        return await ctx.send(embed=embed)

    import secrets
    pin = f"{secrets.randbelow(9000) + 1000}"  # Génère un code aléatoire à 4 chiffres (1000-9999)

    embed = discord.Embed(
        title="🔑 Connexion à Pronote",
        description=(
            f"1. Sur Pronote Web : **À côté de votre prénom**, cliquez sur le logo **QR Code**.\n"
            f"2. Dans **Code de vérification à 4 chiffres**, saisissez : **`{pin}`**\n"
            f"3. Collez ensuite le **JSON du QR Code** directement dans ce chat.\n\n"
            f"⚠️ **Sécurité** : Ces informations donnent un accès direct à votre compte scolaire. Ne partagez jamais ce code PIN ni le contenu du QR Code avec qui que ce soit.\n\n"
            f"*(⏱️ En attente de votre message...)*"
        ),
        color=discord.Color.blue()
    )
    msg_prompt = await ctx.send(embed=embed)

    def check(m: discord.Message):
        return m.author.id == ctx.author.id and isinstance(m.channel, discord.DMChannel)

    try:
        reply_msg = await bot.wait_for("message", check=check, timeout=300.0)
    except asyncio.TimeoutError:
        embed_timeout = discord.Embed(
            title="⏱️ Délai dépassé",
            description="Aucun message reçu. Tapez `!login` lorsque vous êtes prêt.",
            color=discord.Color.orange()
        )
        return await msg_prompt.edit(embed=embed_timeout)

    # Récupérer et supprimer immédiatement le message contenant le JSON sensible
    qr_json = reply_msg.content.strip()
    try:
        await reply_msg.delete()
    except Exception:
        pass

    msg_status = await ctx.send("⏳ Authentification en cours avec PRONOTE...")
    success, reply = pronote.login_with_qrcode(qr_json, pin)

    if success:
        await run_autocheck_cycle(send_notifications=False)
        embed_success = discord.Embed(
            title="✅ Connexion Pronote réussie",
            description=reply,
            color=discord.Color.green()
        )
        embed_success.set_footer(text="Vous pouvez maintenant utiliser !edt, !devoirs, !notes, etc.")
        await msg_status.edit(content=None, embed=embed_success)
    else:
        embed_fail = discord.Embed(
            title="❌ Échec de connexion",
            description=f"{reply}\n\n*Assurez-vous d'avoir bien tapé le code `{pin}` lors de la création du QR Code sur Pronote.*",
            color=discord.Color.red()
        )
        await msg_status.edit(content=None, embed=embed_fail)

@bot.command(name="logout")
async def cmd_logout(ctx: commands.Context):
    """Déconnecte le compte Pronote et supprime les credentials."""
    pronote.logout()
    embed = discord.Embed(
        title="ℹ️ Déconnexion effectuée",
        description="Les identifiants locaux ont été supprimés avec succès.",
        color=discord.Color.blue()
    )
    await ctx.send(embed=embed)

@bot.command(name="status")
async def cmd_status(ctx: commands.Context):
    """Affiche le statut de connexion et de l'autocheck."""
    client = pronote.get_client()
    connected = client is not None and client.logged_in
    name = client.info.name if connected and client.info else "Non connecté"

    embed = discord.Embed(
        title="📊 Statut du Bot Pronote",
        color=discord.Color.green() if connected else discord.Color.red(),
        timestamp=datetime.datetime.now()
    )
    embed.add_field(name="Compte Pronote", value=f"{'🟢 Connecté' if connected else '🔴 Déconnecté'} ({name})", inline=False)
    embed.add_field(name="Autocheck", value=f"{'🟢 Actif' if autocheck_task.is_running() else '🔴 Inactif'} (toutes les {AUTOCHECK_INTERVAL_MINUTES} min)", inline=True)
    embed.add_field(name="Récap du matin", value=f"⏰ Programmée à {MORNING_RECAP_TIME}", inline=True)
    await ctx.send(embed=embed)

@bot.command(name="edt")
@commands.cooldown(1, 5, commands.BucketType.user)
async def cmd_edt(ctx: commands.Context, target: str = "aujourdhui"):
    """Affiche l'emploi du temps (!edt, !edt demain, ou !edt JJ/MM)."""
    client = pronote.get_client()
    if not client:
        return await ctx.send("❌ Vous n'êtes pas connecté à Pronote. Tapez `!login` pour vous connecter.")

    today = datetime.date.today()
    target_clean = target.lower().strip()
    if target_clean in ["aujourdhui", "today", "auj"]:
        target_date = today
        title = "📅 Emploi du temps d'aujourd'hui"
    elif target_clean in ["demain", "tomorrow"]:
        target_date = today + datetime.timedelta(days=1)
        title = "📅 Emploi du temps de demain"
    else:
        try:
            # Format JJ/MM ou JJ/MM/AAAA
            parts = target_clean.split("/")
            if len(parts) == 2:
                target_date = datetime.date(today.year, int(parts[1]), int(parts[0]))
            elif len(parts) == 3:
                target_date = datetime.date(int(parts[2]), int(parts[1]), int(parts[0]))
            else:
                raise ValueError
            title = f"📅 Emploi du temps"
        except Exception:
            return await ctx.send("⚠️ Format de date invalide. Utilisez `!edt`, `!edt demain` ou `!edt JJ/MM`.")

    embed = build_edt_embed(client, target_date, title_prefix=title)
    await ctx.send(embed=embed)

@bot.command(name="devoirs")
@commands.cooldown(1, 5, commands.BucketType.user)
async def cmd_devoirs(ctx: commands.Context, jours: int = 7):
    """Affiche les devoirs pour les N prochains jours (7 par défaut)."""
    client = pronote.get_client()
    if not client:
        return await ctx.send("❌ Vous n'êtes pas connecté à Pronote. Tapez `!login` pour vous connecter.")

    embed = build_homework_embed(client, max_days=jours)
    await ctx.send(embed=embed)

@bot.command(name="notes")
@commands.cooldown(1, 5, commands.BucketType.user)
async def cmd_notes(ctx: commands.Context):
    """Affiche les notes et moyennes de la période en cours."""
    client = pronote.get_client()
    if not client:
        return await ctx.send("❌ Vous n'êtes pas connecté à Pronote. Tapez `!login` pour vous connecter.")

    embed = discord.Embed(
        title="📝 Notes et Moyennes",
        color=discord.Color.green(),
        timestamp=datetime.datetime.now()
    )
    try:
        # Périodes à ignorer (évaluations hors cursus classique)
        ignored_names = [
            "évaluation mobilité européenne et internationale",
            "evaluation mobilite europeenne et internationale",
            "hors période",
            "hors periode"
        ]

        valid_periods = [p for p in client.periods if p.name.lower().strip() not in ignored_names]

        # Priorité aux périodes courantes (Trimestre / Semestre / Année)
        real_periods = [p for p in valid_periods if ("trimestre" in p.name.lower() or "semestre" in p.name.lower() or "année" in p.name.lower())]
        target_periods = real_periods if real_periods else valid_periods

        if not target_periods:
            embed.description = "Aucune note ou période disponible."
            return await ctx.send(embed=embed)

        current_period = target_periods[-1]
        embed.title = f"📝 Notes — {current_period.name}"

        # 6 dernières notes
        all_grades = sorted(current_period.grades, key=lambda g: g.date, reverse=True)
        if all_grades:
            recent_lines = []
            for g in all_grades[:6]:
                date_str = g.date.strftime("%d/%m")
                recent_lines.append(f"• **{g.subject.name}** : `{g.grade}/{g.out_of}` ({date_str})")
            embed.add_field(name="📌 Dernières notes reçues", value="\n".join(recent_lines), inline=False)
        else:
            embed.description = "Aucune note enregistrée pour cette période."

        # Moyenne générale
        if hasattr(current_period, "overall_average") and current_period.overall_average:
            embed.add_field(name="🎯 Moyenne Générale", value=f"**{current_period.overall_average}**", inline=False)

    except Exception as e:
        embed.description = f"⚠️ Erreur lors de la récupération des notes : {e}"
        embed.color = discord.Color.red()

    await ctx.send(embed=embed)

@bot.command(name="profil", aliases=["me"])
@commands.cooldown(1, 5, commands.BucketType.user)
async def cmd_profil(ctx: commands.Context):
    """Affiche le profil complet et les informations de l'élève."""
    client = pronote.get_client()
    if not client:
        return await ctx.send("❌ Vous n'êtes pas connecté à Pronote. Tapez `!login` pour vous connecter.")

    info = client.info
    if not info:
        return await ctx.send("⚠️ Impossible de récupérer les informations de profil.")

    embed = discord.Embed(
        title=f"🪪 Profil — {info.name or 'Élève'}",
        color=discord.Color.blue(),
        timestamp=datetime.datetime.now()
    )

    if getattr(info, "class_name", None):
        embed.add_field(name="🏫 Classe", value=info.class_name, inline=True)
    if getattr(info, "establishment", None):
        embed.add_field(name="📍 Établissement", value=info.establishment, inline=True)
    if getattr(info, "delegue", None) is not None:
        embed.add_field(name="⭐ Délégué", value="Oui" if info.delegue else "Non", inline=True)
    if getattr(info, "ine_number", None):
        embed.add_field(name="🔢 Numéro INE", value=f"`{info.ine_number}`", inline=True)
    if getattr(info, "email", None):
        embed.add_field(name="📧 Email", value=info.email, inline=True)
    if getattr(info, "phone", None):
        embed.add_field(name="📞 Téléphone", value=info.phone, inline=True)
    if getattr(info, "address", None):
        embed.add_field(name="🏠 Adresse", value=str(info.address), inline=False)

    file_to_send = None
    if getattr(info, "profile_picture", None) and getattr(info.profile_picture, "data", None):
        try:
            import io
            image_data = info.profile_picture.data
            if image_data:
                file_to_send = discord.File(io.BytesIO(image_data), filename="profile.png")
                embed.set_thumbnail(url="attachment://profile.png")
        except Exception as e:
            logger.warning(f"Impossible de charger la photo de profil : {e}")

    if file_to_send:
        await ctx.send(file=file_to_send, embed=embed)
    else:
        await ctx.send(embed=embed)

@bot.command(name="absences")
@commands.cooldown(1, 5, commands.BucketType.user)
async def cmd_absences(ctx: commands.Context):
    """Affiche le récapitulatif des absences et retards."""
    client = pronote.get_client()
    if not client:
        return await ctx.send("❌ Vous n'êtes pas connecté à Pronote. Tapez `!login` pour vous connecter.")

    embed = discord.Embed(
        title="🚨 Absences & Retards",
        color=discord.Color.red(),
        timestamp=datetime.datetime.now()
    )
    try:
        seen_abs = set()
        unique_absences = []
        for period in client.periods:
            for a in period.absences:
                abs_key = (a.from_date.isoformat(), a.to_date.isoformat(), a.hours, a.justified)
                if abs_key not in seen_abs:
                    seen_abs.add(abs_key)
                    unique_absences.append(a)

        if unique_absences:
            lines = []
            for a in sorted(unique_absences, key=lambda x: x.from_date, reverse=True):
                hours_str = str(a.hours).replace("h00", "h") if getattr(a, "hours", None) else ""
                hours_display = f" ({hours_str})" if hours_str else ""
                reasons_list = [r.name if hasattr(r, "name") else str(r) for r in a.reasons] if getattr(a, "reasons", None) else []
                reasons_str = f" - *{', '.join(reasons_list)}*" if reasons_list else ""
                lines.append(f"• Du {f} au {t}{hours_display} — {just}{reasons_str}")
            embed.description = "\n".join(lines)
        else:
            embed.description = "🎉 Aucune absence enregistrée !"
            embed.color = discord.Color.green()
    except Exception as e:
        embed.description = f"⚠️ Erreur lors de la récupération des absences : {e}"

    await ctx.send(embed=embed)

@bot.command(name="menu")
@commands.cooldown(1, 5, commands.BucketType.user)
async def cmd_menu(ctx: commands.Context, target: str = "aujourdhui"):
    """Affiche le menu de la cantine (!menu ou !menu demain)."""
    client = pronote.get_client()
    if not client:
        return await ctx.send("❌ Vous n'êtes pas connecté à Pronote. Tapez `!login` pour vous connecter.")

    today = datetime.date.today()
    target_date = today if target.lower() not in ["demain", "tomorrow"] else today + datetime.timedelta(days=1)
    embed = build_menu_embed(client, target_date)
    await ctx.send(embed=embed)

@bot.command(name="recap")
@commands.cooldown(1, 10, commands.BucketType.user)
async def cmd_recap(ctx: commands.Context):
    """Déclenche manuellement le récapitulatif complet (EDT + Devoirs + Menu)."""
    client = pronote.get_client()
    if not client:
        return await ctx.send("❌ Vous n'êtes pas connecté à Pronote. Tapez `!login` pour vous connecter.")

    today = datetime.date.today()
    tomorrow = today + datetime.timedelta(days=1)

    await ctx.send(embed=build_edt_embed(client, today, "🌅 Emploi du temps d'aujourd'hui"))
    await ctx.send(embed=build_edt_embed(client, tomorrow, "📅 Emploi du temps de demain"))
    await ctx.send(embed=build_homework_embed(client, max_days=7))
    await ctx.send(embed=build_menu_embed(client, today))

@bot.command(name="autocheck")
@commands.cooldown(1, 10, commands.BucketType.user)
async def cmd_autocheck(ctx: commands.Context, action: str, val: int = None):
    """Configure la surveillance automatique (!autocheck on/off/interval <minutes>)."""
    global AUTOCHECK_INTERVAL_MINUTES
    action = action.lower()

    if action == "on":
        if not autocheck_task.is_running():
            autocheck_task.change_interval(minutes=AUTOCHECK_INTERVAL_MINUTES)
            autocheck_task.start()
        await ctx.send(f"🟢 Surveillance automatique activée (intervalle : {AUTOCHECK_INTERVAL_MINUTES} min).")
    elif action == "off":
        if autocheck_task.is_running():
            autocheck_task.stop()
        await ctx.send("🔴 Surveillance automatique désactivée.")
    elif action == "interval":
        if not val or val < 15:
            return await ctx.send("⚠️ L'intervalle minimum entre les vérifications est de **15 minutes** (ex: `!autocheck interval 15`).")
        AUTOCHECK_INTERVAL_MINUTES = val
        if autocheck_task.is_running():
            autocheck_task.change_interval(minutes=val)
            autocheck_task.restart()
        await ctx.send(f"⏱️ Intervalle d'autocheck mis à jour à **{val} minutes**.")
    elif action == "now":
        await ctx.send("🔄 Lancement immédiat d'une vérification...")
        alerts = await run_autocheck_cycle(send_notifications=True)
        if alerts:
            for alert in alerts:
                await ctx.send(embed=alert)
        else:
            await ctx.send("✅ Aucun nouveau changement détecté.")
    else:
        await ctx.send("⚠️ Action inconnue. Utilisez `!autocheck on`, `!autocheck off`, `!autocheck interval <min>`, ou `!autocheck now`.")

@bot.command(name="help")
async def cmd_help(ctx: commands.Context):
    """Affiche le menu d'aide du bot."""
    embed = discord.Embed(
        title="📖 Commandes du Bot Pronote",
        description="Ce bot est privé et ne répond qu'à son propriétaire en message direct.",
        color=discord.Color.blurple()
    )
    embed.add_field(
        name="🔑 Authentification",
        value=(
            "`!login` : Lier son compte Pronote de manière guidée\n"
            "`!logout` : Déconnecter le compte et supprimer les identifiants locaux\n"
            "`!status` : Afficher l'état de la connexion et de la surveillance"
        ),
        inline=False
    )
    embed.add_field(
        name="📋 Consultation",
        value=(
            "`!profil` : Profil complet de l'élève (classe, INE, adresse, photo)\n"
            "`!edt [demain|JJ/MM]` : Emploi du temps avec matières, profs et salles\n"
            "`!devoirs [jours]` : Devoirs restants (7 jours par défaut)\n"
            "`!notes` : Dernières notes reçues et moyenne générale\n"
            "`!absences` : Historique des absences et retards\n"
            "`!menu [demain]` : Menus du restaurant scolaire\n"
            "`!recap` : Déclencher le récapitulatif complet du matin"
        ),
        inline=False
    )
    embed.add_field(
        name="⚙️ Surveillance Continue (Autocheck)",
        value=(
            "`!autocheck on / off` : Activer ou désactiver la surveillance\n"
            "`!autocheck interval <min>` : Modifier la fréquence de scan (min: 15)\n"
            "`!autocheck now` : Forcer une vérification immédiate"
        ),
        inline=False
    )
    await ctx.send(embed=embed)

if __name__ == "__main__":
    if not DISCORD_TOKEN or DISCORD_TOKEN == "VOTRE_TOKEN_BOT_DISCORD":
        logger.error("DISCORD_TOKEN non defini dans config.py !")
        print("Veuillez renseigner votre DISCORD_TOKEN dans config.py.")
        exit(1)

    if not OWNER_ID or OWNER_ID == 123456789012345678:
        logger.error("OWNER_ID non defini dans config.py !")
        print("Veuillez renseigner votre OWNER_ID dans config.py.")
        exit(1)

    logger.info("Demarrage du bot Discord PRONOTE...")
    bot.run(DISCORD_TOKEN)

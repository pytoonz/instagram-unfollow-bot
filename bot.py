import requests
from time import sleep, time
from urllib.parse import quote
from json import dumps
from hashlib import md5
from random import uniform
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes, ConversationHandler
import logging
import os
from flask import Flask, request

# Enable logging for debugging
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

# States for conversation handler
SESSION_ID_CHOICE, SESSION_ID_INPUT, USERNAME, PASSWORD, TWO_FA_CODE = range(5)

# Store user sessions in memory
user_sessions = {}

# Flask app for webhook
app = Flask(__name__)

class Login:
    def __init__(self, username=None, password=None, sessionid=None):
        self.password = password
        self.username = username
        self.sessionid = sessionid
        self.url = "https://i.instagram.com/api/v1/accounts/login/"
        self.headers = {
            "User-Agent": "Instagram 194.0.0.36.172 Android (29/10; 440dpi; 1080x2340; samsung; SM-G973F; beyond1; exynos9820; en_US; 301492510)",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        self.r = requests.Session()

    def csrfToken(self):
        try:
            res = self.r.get(self.url, headers=self.headers)
            return res.cookies.get("csrftoken", "")
        except Exception as e:
            logger.error(f"Error fetching CSRF token: {e}")
            return ""

    def sessionID(self):
        headers_check = {
            'User-Agent': 'Instagram 194.0.0.36.172 Android (29/10; 440dpi; 1080x2340; samsung; SM-G973F; beyond1; exynos9820; en_US; 301492510)',
            'Cookie': f'csrftoken={md5(str(time()).encode()).hexdigest()}; sessionid={self.sessionid};'
        }
        try:
            response = self.r.get('https://i.instagram.com/api/v1/accounts/current_user/?edit=true', headers=headers_check)
            result = response.json()
            if result.get('status') == "ok":
                return True
            logger.error(f"Session ID validation failed: {result}")
            return False
        except Exception as e:
            logger.error(f"Session ID validation error: {e}")
            return False

    def account(self, two_fa_code=None):
        csrf = self.csrfToken()
        if not csrf:
            return None
        payload = {
            "_csrftoken": csrf,
            "adid": "bbe5bcdb-b1e3-4815-9e3b-9265c0740970",
            "country_codes": [{"country_code": "964", "source": ["default"]}],
            "device_id": "android-",
            "google_tokens": "[]",
            "guid": "064020d6-330c-471d-a7b2-fc1774dc7122",
            "login_attempt_count": 0,
            "password": self.password,
            "phone_id": "824595cb-7bf9-4b40-8075-685df82e23cc",
            "username": self.username
        }
        if two_fa_code:
            payload["two_factor_identifier"] = two_fa_code
        data = f'signed_body=fd5f359e5560870ec4cdc326850186a0ebc0033465fdd7477d727e6bae6d575e.{quote(dumps(payload))}&ig_sig_key_version=4'
        try:
            fi = self.r.post(self.url, headers=self.headers, data=data)
            response_json = fi.json()
            if 'sessionid' in fi.cookies.get_dict():
                return fi.cookies.get('sessionid')
            elif response_json.get('two_factor_required'):
                logger.info("Two-factor authentication required")
                return "2fa_required"
            elif response_json.get('message') == 'checkpoint_required':
                logger.error(f"Checkpoint required: {response_json}")
                return "checkpoint_required"
            else:
                logger.error(f"Login failed: {response_json}")
                return None
        except Exception as e:
            logger.error(f"Login error: {e}")
            return None

async def auto_unfollow(update: Update, context: ContextTypes.DEFAULT_TYPE, sessionid: str):
    user_id = update.effective_user.id
    logger.info(f"Starting auto_unfollow for user {user_id} with session ID: {sessionid[:10]}...")

    if not Login(sessionid=sessionid).sessionID():
        await update.message.reply_text("❌ Session ID is invalid or expired. Please log in again with /login.")
        logger.warning(f"User {user_id} session ID invalid in auto_unfollow")
        return

    cookies = {
        'sessionid': sessionid,
        'csrftoken': md5(str(time()).encode()).hexdigest(),
        'ds_user_id': ''
    }

    headers = {
        'authority': 'www.instagram.com',
        'accept': '*/*',
        'accept-language': 'en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7',
        'x-csrftoken': cookies['csrftoken'],
        'x-ig-app-id': '1217981644879628',
        'x-requested-with': 'XMLHttpRequest',
        'user-agent': 'Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36',
    }

    s = requests.Session()
    s.cookies.set('sessionid', sessionid)
    s.cookies.set('csrftoken', cookies['csrftoken'])

    url_me = "https://i.instagram.com/api/v1/accounts/current_user/?edit=true"
    headers_check = {
        'User-Agent': 'Instagram 194.0.0.36.172 Android (29/10; 440dpi; 1080x2340; samsung; SM-G973F; beyond1; exynos9820; en_US; 301492510)',
        'Cookie': f'csrftoken={cookies["csrftoken"]}; sessionid={sessionid};'
    }
    try:
        logger.info(f"User {user_id} fetching user ID")
        r = s.get(url_me, headers=headers_check)
        r.raise_for_status()
        result = r.json()
        if result.get('status') != 'ok':
            await update.message.reply_text(f"❌ Failed to fetch user ID: {result.get('message', 'Unknown error')}")
            logger.error(f"User {user_id} failed to fetch user ID: {result}")
            return
        uid = result['user']['pk']
        cookies['ds_user_id'] = str(uid)
        logger.info(f"User {user_id} fetched user ID: {uid}")
    except Exception as e:
        await update.message.reply_text(f"❌ Error fetching user ID: {e}")
        logger.error(f"User {user_id} error fetching user ID: {e}")
        return

    await update.message.reply_text("Starting auto unfollow process...")
    logger.info(f"User {user_id} starting to fetch following list")

    followings = []
    max_id = ''
    retries = 3
    while True:
        url = f'https://www.instagram.com/api/v1/friendships/{cookies["ds_user_id"]}/following/?count=50'
        if max_id:
            url += f'&max_id={max_id}'
        for attempt in range(retries):
            try:
                logger.info(f"User {user_id} fetching following list, attempt {attempt + 1}")
                res = s.get(url, headers=headers)
                res.raise_for_status()
                js = res.json()
                if js.get('status') != 'ok':
                    await update.message.reply_text(f"❌ Failed to fetch following list: {js.get('message', 'Unknown error')}")
                    logger.error(f"User {user_id} failed to fetch following list: {js}")
                    return
                followings.extend(js.get('users', []))
                max_id = js.get('next_max_id')
                logger.info(f"User {user_id} fetched {len(js.get('users', []))} users, next_max_id: {max_id}")
                break
            except Exception as e:
                if attempt < retries - 1:
                    logger.warning(f"User {user_id} error fetching following list, attempt {attempt + 1}: {e}. Retrying...")
                    sleep(uniform(3.0, 5.0))
                    continue
                await update.message.reply_text(f"❌ Error fetching following list: {e}")
                logger.error(f"User {user_id} error fetching following list after {retries} attempts: {e}")
                return
        if not max_id:
            break
        sleep(uniform(3.0, 5.0))

    if not followings:
        await update.message.reply_text("❌ No users found to unfollow. Please check if you are following any accounts.")
        logger.info(f"User {user_id} has no users to unfollow")
        return

    for idx, user in enumerate(followings, 1):
        uid_to_unfollow = user['pk']
        uname = user['username']
        data = {
            'container_module': 'profile',
            'user_id': str(uid_to_unfollow),
            'jazoest': '22790',
        }
        for attempt in range(retries):
            try:
                logger.info(f"User {user_id} attempting to unfollow {uname}, attempt {attempt + 1}")
                res = s.post(
                    f'https://www.instagram.com/api/v1/friendships/destroy/{uid_to_unfollow}/',
                    headers=headers,
                    data=data,
                )
                res.raise_for_status()
                result = res.json()
                if result.get('status') == 'ok':
                    await update.message.reply_text(f"{idx} ✅ Unfollowed - {uname}")
                    logger.info(f"User {user_id} unfollowed {uname}")
                else:
                    await update.message.reply_text(f"{idx} ❌ Failed - {uname}: {result.get('message', 'Unknown error')}")
                    logger.warning(f"User {user_id} failed to unfollow {uname}: {result}")
                break
            except Exception as e:
                if attempt < retries - 1:
                    logger.warning(f"User {user_id} error unfollowing {uname}, attempt {attempt + 1}: {e}. Retrying...")
                    sleep(uniform(3.0, 5.0))
                    continue
                await update.message.reply_text(f"{idx} ⚠️ Error unfollowing {uname}: {e}")
                logger.error(f"User {user_id} error unfollowing {uname} after {retries} attempts: {e}")
            sleep(uniform(3.0, 5.0))

    await update.message.reply_text("✅ Unfollow process completed!")
    logger.info(f"User {user_id} completed unfollow process")

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.info("Received /start command")
    await update.message.reply_text(
        "Welcome to the Instagram Unfollow Bot! 🤖\n"
        "Use /login to log in with your Instagram credentials or session ID.\n"
        "Use /unfollow to start the unfollow process.\n"
        "Use /cancel to cancel any ongoing operation."
    )

async def login(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.info("Received /login command")
    await update.message.reply_text(
        "How would you like to log in?\n"
        "1️⃣ Send '1' to log in with Session ID.\n"
        "2️⃣ Send '2' to log in with Username & Password."
    )
    return SESSION_ID_CHOICE

async def session_id_choice(update: Update, context: ContextTypes.DEFAULT_TYPE):
    choice = update.message.text.strip()
    user_id = update.effective_user.id
    logger.info(f"User {user_id} sent choice: {choice}")

    if choice == '1':
        await update.message.reply_text("Please enter your Instagram Session ID:")
        return SESSION_ID_INPUT
    elif choice == '2':
        await update.message.reply_text("Please enter your Instagram Username:")
        return USERNAME
    else:
        logger.warning(f"Invalid choice received: {choice}")
        await update.message.reply_text("❌ Invalid option. Please send '1' for Session ID or '2' for Username & Password.")
        return SESSION_ID_CHOICE

async def get_session_id(update: Update, context: ContextTypes.DEFAULT_TYPE):
    session_id = update.message.text.strip()
    user_id = update.effective_user.id
    logger.info(f"User {user_id} sent Session ID: {session_id[:10]}...")

    if Login(sessionid=session_id).sessionID():
        user_sessions[user_id] = session_id
        await update.message.reply_text(f"✅ Login successful! Session ID stored.")
        logger.info(f"User {user_id} logged in successfully with Session ID")
        return ConversationHandler.END
    else:
        await update.message.reply_text("❌ Invalid or expired Session ID. Please try again or choose another login method.")
        logger.warning(f"User {user_id} provided invalid or expired Session ID")
        return SESSION_ID_INPUT

async def get_username(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data['username'] = update.message.text.strip()
    logger.info(f"User {update.effective_user.id} sent username: {context.user_data['username']}")
    await update.message.reply_text("Please enter your Instagram Password:")
    return PASSWORD

async def get_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    password = update.message.text.strip()
    username = context.user_data.get('username')
    user_id = update.effective_user.id
    logger.info(f"User {user_id} sent password for username: {username}")

    login_instance = Login(username=username, password=password)
    result = login_instance.account()
    if result == "2fa_required":
        await update.message.reply_text("Two-factor authentication required. Please enter the 2FA code sent to your device:")
        context.user_data['login_instance'] = login_instance
        return TWO_FA_CODE
    elif result == "checkpoint_required":
        await update.message.reply_text(
            "❌ Instagram flagged this as a suspicious login attempt. Please approve the login on Instagram and try again."
        )
        logger.warning(f"User {user_id} login failed due to checkpoint_required")
        return USERNAME
    elif result:
        user_sessions[user_id] = result
        await update.message.reply_text(f"✅ Login successful! Session ID: {result}")
        logger.info(f"User {user_id} logged in successfully with username/password")
        return ConversationHandler.END
    else:
        await update.message.reply_text(
            "❌ Login failed. Username or password might be incorrect, or Instagram blocked the attempt. Please check your credentials and try again."
        )
        logger.warning(f"User {user_id} login failed with username/password")
        return USERNAME

async def get_two_fa_code(update: Update, context: ContextTypes.DEFAULT_TYPE):
    two_fa_code = update.message.text.strip()
    user_id = update.effective_user.id
    login_instance = context.user_data.get('login_instance')
    logger.info(f"User {user_id} sent 2FA code")

    if login_instance:
        result = login_instance.account(two_fa_code=two_fa_code)
        if result == "checkpoint_required":
            await update.message.reply_text(
                "❌ Instagram flagged this as a suspicious login attempt. Please approve the login on Instagram and try again."
            )
            logger.warning(f"User {user_id} 2FA login failed due to checkpoint_required")
            return ConversationHandler.END
        elif result:
            user_sessions[user_id] = result
            await update.message.reply_text(f"✅ Login successful! Session ID: {result}")
            logger.info(f"User {user_id} logged in successfully with 2FA")
            return ConversationHandler.END
        else:
            await update.message.reply_text("❌ Invalid 2FA code or login failed. Please try again.")
            logger.warning(f"User {user_id} 2FA login failed")
            return TWO_FA_CODE
    else:
        await update.message.reply_text("❌ Session expired. Please start login again with /login.")
        logger.warning(f"User {user_id} 2FA login failed due to missing login instance")
        return ConversationHandler.END

async def unfollow(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    session_id = user_sessions.get(user_id)
    logger.info(f"User {user_id} requested /unfollow")

    if not session_id:
        await update.message.reply_text("❌ Please log in first using /login.")
        logger.warning(f"User {user_id} attempted /unfollow without logging in")
        return

    await auto_unfollow(update, context, session_id)

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.info(f"User {update.effective_user.id} sent /cancel")
    await update.message.reply_text("✅ Operation cancelled.")
    return ConversationHandler.END

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.error(f"Update {update} caused error: {context.error}")
    try:
        await update.message.reply_text(f"❌ An error occurred: {context.error}")
    except Exception as e:
        logger.error(f"Error sending error message: {e}")

# Global application instance
application = None

@app.route('/<token>', methods=['POST'])
async def webhook(token):
    global application
    expected_token = os.getenv('TELEGRAM_BOT_TOKEN')
    if token != expected_token:
        logger.warning("Invalid webhook token received")
        return "Invalid token", 403
    if not application:
        logger.error("Application not initialized")
        return "Server error", 500
    try:
        data = request.get_json()
        update = Update.de_json(data, application.bot)
        await application.process_update(update)
        return 'OK', 200
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return "Error processing update", 500

async def set_webhook():
    global application
    webhook_url = os.getenv('WEBHOOK_URL')
    if not webhook_url:
        logger.error("WEBHOOK_URL environment variable not set!")
        return
    try:
        await application.bot.set_webhook(f"{webhook_url}/{os.getenv('TELEGRAM_BOT_TOKEN')}")
        logger.info(f"Webhook set to {webhook_url}")
    except Exception as e:
        logger.error(f"Failed to set webhook: {e}")

def main():
    global application
    token = os.getenv('TELEGRAM_BOT_TOKEN')
    if not token:
        logger.error("TELEGRAM_BOT_TOKEN environment variable not set!")
        return

    application = Application.builder().token(token).build()

    conv_handler = ConversationHandler(
        entry_points=[CommandHandler('login', login)],
        states={
            SESSION_ID_CHOICE: [MessageHandler(filters.TEXT & ~filters.COMMAND, session_id_choice)],
            SESSION_ID_INPUT: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_session_id)],
            USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_username)],
            PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_password)],
            TWO_FA_CODE: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_two_fa_code)],
        },
        fallbacks=[CommandHandler('cancel', cancel)],
    )

    application.add_handler(CommandHandler('start', start))
    application.add_handler(conv_handler)
    application.add_handler(CommandHandler('unfollow', unfollow))
    application.add_error_handler(error_handler)

    # Initialize application and set webhook
    application.run_async(set_webhook())
    logger.info("Starting Flask server...")
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 10000)))

if __name__ == "__main__":
    main()

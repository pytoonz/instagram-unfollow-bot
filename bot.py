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

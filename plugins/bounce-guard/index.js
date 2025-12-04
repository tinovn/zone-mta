'use strict';

module.exports.title = 'ZoneMTA Security Shield';

module.exports.init = function (app, done) {
    const redisClient = app.db.redis;
    const logger = app.logger;

    // --- CẤU HÌNH ---
    const CONFIG = {
        keyPrefix: 'security_shield:',

        // 1. Rate Limit: 20 mail / 1 giây
        rateLimitWindow: 1,
        rateLimitMax: 20,

        // 2. Bounce Guard: Chặn nếu gửi lỗi nhiều
        recipientBlockTTL: 7200, // 7 ngày
        senderBounceLimit: 20,     // 20 lỗi
        senderBounceBlockTTL: 3600,// Khoá 1 giờ
        senderCountTTL: 86400      // Reset sau 24h
    };

    // Load config từ file toml (nếu có)
    try {
        let fileConfig = {};
        if (app.config.plugins['bounce-guard']) fileConfig = app.config.plugins['bounce-guard'];
        else if (app.config.plugins['plugins/bounce-guard']) fileConfig = app.config.plugins['plugins/bounce-guard'];
        if (fileConfig['bounce-guard']) fileConfig = fileConfig['bounce-guard'];

        if (fileConfig.rules && fileConfig.rules.rate && fileConfig.rules.rate.limit) {
            CONFIG.rateLimitMax = fileConfig.rules.rate.limit;
        }
    } catch (e) {}

    logger.info('SecurityShield', `🛡️ Plugin Loaded. Rate Limit: ${CONFIG.rateLimitMax}/s`);

    if (!redisClient) return done();

    // --- HOOK 1: KIỂM TRA ĐẦU VÀO (sender:fetch) ---
    app.addHook('sender:fetch', (delivery, next) => {
        // --- FIX LỖI CRASH (delivery.to.toLowerCase) ---
        // Chúng ta phải đảm bảo biến này là String trước khi xử lý
        let recipient = '';
        if (delivery.to) {
            if (Array.isArray(delivery.to)) recipient = delivery.to[0]; // Nếu là mảng, lấy cái đầu
            else recipient = delivery.to;
        }
        recipient = String(recipient).toLowerCase(); // Ép kiểu về String an toàn

        let sender = '';
        if (delivery.from) sender = String(delivery.from).toLowerCase();
        // ------------------------------------------------

        // 1. Kiểm tra KHOÁ CỨNG (Do Bounce nhiều)
        const senderBlockKey = `${CONFIG.keyPrefix}blocked_sender:${sender}`;
        redisClient.get(senderBlockKey, (err, blockReason) => {
            if (blockReason) {
                // Trả về lỗi 550 để chặn (ZoneMTA sẽ log ERR! ở đây, là bình thường)
                return next(new Error(`550 5.7.1 Account blocked: ${blockReason}`));
            }

            // 2. Kiểm tra NGƯỜI NHẬN (Mail chết)
            const rcptKey = `${CONFIG.keyPrefix}bad_rcpt:${recipient}`;
            redisClient.get(rcptKey, (err, isBad) => {
                if (isBad) {
                    return next(new Error('550 5.1.1 Recipient blocked by Bounce Guard'));
                }

                // 3. Kiểm tra TỐC ĐỘ (Rate Limit)
                checkRateLimit(sender, next);
            });
        });
    });

    // Hàm kiểm tra tốc độ
    function checkRateLimit(sender, next) {
        if (!sender) return next();

        const rateKey = `${CONFIG.keyPrefix}rate:${sender}`;

        redisClient.incr(rateKey, (err, currentRate) => {
            if (err) return next();

            if (currentRate === 1) redisClient.expire(rateKey, CONFIG.rateLimitWindow);

            if (currentRate > CONFIG.rateLimitMax) {
                // Quá tốc độ -> Trả lỗi 421 (Gửi lại sau) -> Không mất mail
                return next(new Error(`421 4.7.0 Speed limit exceeded (${currentRate}/${CONFIG.rateLimitMax}). Please wait.`));
            } else {
                next();
            }
        });
    }

    // --- HOOK 2: BẮT LỖI BOUNCE (sender:responseError) ---
    app.addHook('sender:responseError', (delivery, connection, err, next) => {
        // --- FIX LỖI CRASH ---
        let recipient = '';
        if (delivery && delivery.to) {
             if (Array.isArray(delivery.to)) recipient = delivery.to[0];
             else recipient = delivery.to;
        }
        recipient = String(recipient).toLowerCase();

        let sender = '';
        if (delivery && delivery.from) sender = String(delivery.from).toLowerCase();
        // ---------------------

        const errorText = err.response || err.message || '';

        // Chỉ bắt lỗi 550 hoặc 5xx
        if (errorText.includes('550') || (err.code && err.code >= 500)) {
            logger.info('SecurityShield', `Bounce detected: ${recipient} (Sender: ${sender})`);

            // Chặn người nhận chết
            redisClient.setex(`${CONFIG.keyPrefix}bad_rcpt:${recipient}`, CONFIG.recipientBlockTTL, '1');

            // Phạt người gửi
            if (sender) {
                const bounceCountKey = `${CONFIG.keyPrefix}bounce_count:${sender}`;
                redisClient.incr(bounceCountKey, (err, count) => {
                    if (count === 1) redisClient.expire(bounceCountKey, CONFIG.senderCountTTL);

                    if (count > CONFIG.senderBounceLimit) {
                        const blockKey = `${CONFIG.keyPrefix}blocked_sender:${sender}`;
                        // Khoá 1 giờ -> Lý do: TOO_MANY_BOUNCES
                        redisClient.setex(blockKey, CONFIG.senderBounceBlockTTL, 'TOO_MANY_BOUNCES', () => {
                            logger.warn('SecurityShield', `🚫 BLOCKING SENDER: ${sender} (High bounce rate)`);
                        });
                    }
                });
            }
        }
        next();
    });

    done();
};

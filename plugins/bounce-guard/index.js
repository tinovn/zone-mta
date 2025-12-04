'use strict';

module.exports.title = 'Bounce Guard Pro';

module.exports.init = function (app, done) {
    const redisClient = app.db.redis;

    // --- CẤU HÌNH ---
    const CONFIG = {
        keyPrefix: 'bounce_guard:',
        recipientBlockTTL: 604800, // Chặn người nhận 7 ngày
        senderLimit: 20,           // Giới hạn lỗi cho phép
        senderBlockTTL: 3600,      // Phạt người gửi 1 giờ
        senderCountTTL: 86400      // Reset bộ đếm sau 24h
    };

    console.log('[BG-PRO] PLUGIN LOADED. Using hooks: sender:fetch & sender:responseError');

    if (!redisClient) return done();

    // --- HOOK 1: CHẶN GỬI (Dùng sender:fetch thay vì sender:rcpt) ---
    // Chạy khi lấy mail từ hàng đợi ra
    app.addHook('sender:fetch', (delivery, next) => {
        const recipient = delivery.to;
        const sender = delivery.from;

        // 1. Kiểm tra SENDER (Người gửi có bị khóa mõm không?)
        if (sender) {
            const senderBlockKey = `${CONFIG.keyPrefix}blocked_sender:${sender}`;
            redisClient.get(senderBlockKey, (err, isBlocked) => {
                if (isBlocked) {
                    console.log(`[BG-PRO] ⛔ SENDER BLOCKED: ${sender}`);
                    // Trả về lỗi để ZoneMTA hủy mail này
                    return next(new Error('550 5.7.1 Your account is temporarily blocked due to high bounce rate.'));
                }

                // Nếu Sender sạch, check tiếp Recipient
                checkRecipient();
            });
        } else {
            checkRecipient();
        }

        function checkRecipient() {
            const rcptKey = `${CONFIG.keyPrefix}bad_rcpt:${recipient}`;
            redisClient.get(rcptKey, (err, isBad) => {
                if (isBad) {
                    console.log(`[BG-PRO] ⛔ RECIPIENT BLOCKED: ${recipient}`);
                    return next(new Error('550 5.1.1 Recipient blocked by Bounce Guard'));
                }
                // Nếu tất cả đều sạch -> Cho đi tiếp
                next();
            });
        }
    });

    // --- HOOK 2: BẮT LỖI & PHẠT (sender:responseError) ---
    app.addHook('sender:responseError', (delivery, connection, err, next) => {
        const recipient = delivery.to;
        const sender = delivery.from;

        const errorText = err.response || err.message || '';

        // Chỉ bắt lỗi Hard Bounce (5xx) hoặc có chữ "550"
        if (errorText.includes('550') || (err.code && err.code >= 500)) {
            console.log(`[BG-PRO] 🚨 BOUNCE DETECTED: ${recipient}`);

            // A. Lưu người nhận vào sổ đen (Logic cũ)
            const rcptKey = `${CONFIG.keyPrefix}bad_rcpt:${recipient}`;
            redisClient.setex(rcptKey, CONFIG.recipientBlockTTL, '1');

            // B. Phạt người gửi (Logic mới)
            if (sender) {
                const counterKey = `${CONFIG.keyPrefix}sender_count:${sender}`;

                // Tăng đếm lỗi
                redisClient.incr(counterKey, (redisErr, count) => {
                    if (redisErr) return;

                    // Nếu là lỗi đầu tiên, đặt hạn sử dụng cho bộ đếm (24h)
                    if (count === 1) redisClient.expire(counterKey, CONFIG.senderCountTTL);

                    console.log(`[BG-PRO] Sender ${sender} errors: ${count}/${CONFIG.senderLimit}`);

                    // Nếu vượt quá giới hạn -> KHOÁ
                    if (count > CONFIG.senderLimit) {
                        const senderBlockKey = `${CONFIG.keyPrefix}blocked_sender:${sender}`;

                        redisClient.setex(senderBlockKey, CONFIG.senderBlockTTL, '1', () => {
                            console.log(`[BG-PRO] 🛑 LIMIT EXCEEDED! Blocking sender ${sender} for 1 hour.`);
                        });
                    }
                });
            }
        }

        next();
    });

    done();
};

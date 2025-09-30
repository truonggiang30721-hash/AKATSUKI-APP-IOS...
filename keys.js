(function () {
  const ZALO_RENEW_URL = "https://iosclub.rf.gd"; 

  // ====== DANH MỤC KEY ======
  window.UCHIHA_KEYS = {
    "TrGiang": { plan:{days:30},  note:"Menu Bá Sàn" },
    "VuTruongGiang": { plan:{days:30}, note:"Vutruonggiangvipro" }
  };

  // ====== STORAGE ======
  const STORE_BIND   = "uchiha_bindings_v2";    // { keyId:{ fp, start, exp, locked?, reason?, lockAt? } }
  const STORE_FAILS  = "uchiha_fail_counts_v2"; // { keyId:number }
  const FAIL_LIMIT   = 100;

  // ====== UTILS ======
  const now = () => Date.now();
  const load = (k, fb) => { try{ return JSON.parse(localStorage.getItem(k) || JSON.stringify(fb)); }catch{ return fb; } };
  const save = (k, v) => localStorage.setItem(k, JSON.stringify(v));
  const toKeyId = (s) => s.trim();
  function parsePlanStart(startISO, plan){
    const d = new Date(startISO);
    if (plan?.days)   d.setDate(d.getDate() + Number(plan.days||0));
    if (plan?.months) d.setMonth(d.getMonth() + Number(plan.months||0));
    return d.getTime();
  }
  async function sha256Hex(str){
    const enc = new TextEncoder().encode(str);
    const buf = await crypto.subtle.digest("SHA-256", enc);
    return [...new Uint8Array(buf)].map(b=>b.toString(16).padStart(2,"0")).join("");
  }
  function getFingerprint(){
    const parts = [
      navigator.userAgent,
      navigator.language,
      screen.width+"x"+screen.height+"@"+(window.devicePixelRatio||1),
      navigator.hardwareConcurrency||0,
      Intl.DateTimeFormat().resolvedOptions().timeZone||""
    ];
    return btoa(parts.join("|"));
  }

  // ====== CORE API ======
  const API = {
    renewUrl(){ return ZALO_RENEW_URL; },

    /** Xác thực key + bind 1 thiết bị; hết hạn → lock vĩnh viễn */
    async verifyKey(inputKey){
      const keyRaw = inputKey.trim();
      if(!keyRaw) return { ok:false, msg:"Hãy nhập key." };

      // tra meta
      let meta = window.UCHIHA_KEYS[keyRaw];
      if(!meta){
        const hx = await sha256Hex(keyRaw);
        for(const k in window.UCHIHA_KEYS){
          if(k.startsWith("sha256:") && k.slice(7).toLowerCase() === hx.toLowerCase()){
            meta = window.UCHIHA_KEYS[k]; break;
          }
        }
      }
      if(!meta) return API._fail(keyRaw, "Key không tồn tại hoặc sai.", "not_found");

      const keyId = toKeyId(keyRaw);
      const binds = load(STORE_BIND, {});
      const fails = load(STORE_FAILS, {});
      const rec   = binds[keyId] || {};
      const fp    = getFingerprint();

      // đang bị khoá?
      if (rec.locked) {
        const why = rec.reason || "locked";
        const msg =
          why === "expired_lock"   ? "Key đã hết hạn và bị khoá. Vui lòng liên hệ gia hạn." :
          why === "device_mismatch"? "Key đã gắn với thiết bị khác. Truy cập bị chặn." :
          why === "too_many_fail"  ? `Key bị khoá do nhập sai ${FAIL_LIMIT} lần.` :
                                      "Key đang bị khoá.";
        return { ok:false, msg, reason:why, renew:ZALO_RENEW_URL };
      }

      // quá số lần sai → khoá
      if ((fails[keyId]||0) >= FAIL_LIMIT) {
        rec.locked = true; rec.reason = "too_many_fail"; rec.lockAt = now();
        binds[keyId] = rec; save(STORE_BIND, binds);
        return { ok:false, msg:`Key bị khoá do nhập sai ${FAIL_LIMIT} lần. Nhấn “Gia hạn/Liên hệ”.`, reason:"too_many_fail", renew:ZALO_RENEW_URL };
      }

      // ưu tiên exp tuyệt đối trong meta
      if (meta.exp) {
        const expAbs = new Date(meta.exp).getTime();
        if (expAbs && now() > expAbs) {
          rec.locked = true; rec.reason = "expired_lock"; rec.lockAt = now();
          binds[keyId] = rec; save(STORE_BIND, binds);
          return { ok:false, msg:"Key đã hết hạn và bị khoá. Vui lòng liên hệ gia hạn.", reason:"expired_lock", renew:ZALO_RENEW_URL };
        }
      }

      // đã từng bind?
      if (rec.fp) {
        if (rec.fp !== fp) {
          rec.locked = true; rec.reason = "device_mismatch"; rec.lockAt = now();
          binds[keyId] = rec; save(STORE_BIND, binds);
          return { ok:false, msg:"Key đã gắn với thiết bị khác. Truy cập bị chặn.", reason:"device_mismatch", renew:ZALO_RENEW_URL };
        }
        const expAt = meta.exp ? new Date(meta.exp).getTime() : (rec.exp||0);
        if (expAt && now() > expAt) {
          rec.locked = true; rec.reason = "expired_lock"; rec.lockAt = now();
          binds[keyId] = rec; save(STORE_BIND, binds);
          return { ok:false, msg:"Key đã hết hạn và bị khoá. Vui lòng liên hệ gia hạn.", reason:"expired_lock", renew:ZALO_RENEW_URL };
        }
        return { ok:true, msg:"Xác thực thành công.", exp:expAt||null, note:meta.note||"" };
      }

      // lần đầu bind
      const startISO = new Date().toISOString();
      const expTime  = (meta.exp) ? new Date(meta.exp).getTime()
                                  : (meta.plan ? parsePlanStart(startISO, meta.plan) : 0);

      // quá hạn ngay lúc bind → khoá luôn
      if (expTime && now() > expTime) {
        binds[keyId] = { fp, start:startISO, exp:expTime||0, locked:true, reason:"expired_lock", lockAt:now() };
        save(STORE_BIND, binds);
        return { ok:false, msg:"Key đã hết hạn và bị khoá. Vui lòng liên hệ gia hạn.", reason:"expired_lock", renew:ZALO_RENEW_URL };
      }

      // bind hợp lệ
      binds[keyId] = { fp, start:startISO, exp:expTime||0, locked:false };
      save(STORE_BIND, binds);

      // clear fail counter nếu có
      if (fails[keyId]) { delete fails[keyId]; save(STORE_FAILS, fails); }

      return { ok:true, msg:"Key đã kích hoạt cho thiết bị này.", exp:expTime||null, note:meta.note||"" };
    },

    /** ghi nhận nhập sai + tự khoá nếu vượt limit */
    _fail(keyRaw, message, reason){
      const keyId = toKeyId(keyRaw);
      const fails = load(STORE_FAILS, {});
      fails[keyId] = (fails[keyId]||0) + 1;
      if (fails[keyId] >= FAIL_LIMIT) {
        save(STORE_FAILS, fails);
        const binds = load(STORE_BIND, {});
        const rec = binds[keyId] || {};
        rec.locked = true; rec.reason = "too_many_fail"; rec.lockAt = now();
        binds[keyId] = rec; save(STORE_BIND, binds);
        return { ok:false, msg:`Key bị khoá do nhập sai ${FAIL_LIMIT} lần. Nhấn “Gia hạn/Liên hệ”.`, reason:"too_many_fail", renew:ZALO_RENEW_URL };
      }
      save(STORE_FAILS, fails);
      return { ok:false, msg:message||"Key không hợp lệ.", reason:reason||"invalid" };
    },

    /** Admin reset: gỡ bind & fail counter (chỉ khi cần) */
    adminReset(keyRaw){
      const keyId = toKeyId(keyRaw);
      const binds = load(STORE_BIND, {}); const fails = load(STORE_FAILS, {});
      delete binds[keyId]; delete fails[keyId];
      save(STORE_BIND, binds); save(STORE_FAILS, fails);
      return { ok:true, msg:"Đã xoá bind & fail counter. Key sẵn sàng kích hoạt lại." };
    }
  };

  // Public API
  window.UCHIHA = API;
})();
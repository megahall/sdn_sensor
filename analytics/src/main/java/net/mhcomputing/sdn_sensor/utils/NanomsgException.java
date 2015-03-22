package net.mhcomputing.sdn_sensor.utils;

public class NanomsgException extends RuntimeException {
    private static final long serialVersionUID = 8148560283785778452L;

    public NanomsgException() {
        super();
    }

    public NanomsgException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

    public NanomsgException(String message, Throwable cause) {
        super(message, cause);
    }

    public NanomsgException(String message) {
        super(message);
    }

    public NanomsgException(Throwable cause) {
        super(cause);
    }
}

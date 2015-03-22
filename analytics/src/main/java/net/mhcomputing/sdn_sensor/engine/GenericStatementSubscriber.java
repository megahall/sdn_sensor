package net.mhcomputing.sdn_sensor.engine;

import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class GenericStatementSubscriber {
    private static Logger log =
        LoggerFactory.getLogger(GenericStatementSubscriber.class);
    
    private AtomicLong seqNum;
    
    public GenericStatementSubscriber() {
        seqNum = new AtomicLong(1);
    }
    
    public void update(Object[] row) {
        long s = seqNum.getAndIncrement();
        if (s % 100000 == 0) {
            log.info("generic subscriber received event ID {}", s);
        }
    }
}

package net.mhcomputing.sdn_sensor.engine;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.espertech.esper.client.hook.ExceptionHandler;
import com.espertech.esper.client.hook.ExceptionHandlerContext;
import com.espertech.esper.client.hook.ExceptionHandlerFactory;
import com.espertech.esper.client.hook.ExceptionHandlerFactoryContext;

public class EsperExceptionHandler implements ExceptionHandlerFactory, ExceptionHandler {
    private static Logger log =
        LoggerFactory.getLogger(EsperExceptionHandler.class);
    
    public EsperExceptionHandler() {
        // TODO Auto-generated constructor stub
    }

    @Override
    public ExceptionHandler getHandler(ExceptionHandlerFactoryContext context) {
        log.info("registered custom Esper engine exception handler");
        return this;
    }

    @SuppressWarnings("unused")
    @Override
    public void handle(ExceptionHandlerContext context) {
        String    engineName    = context.getEngineURI();
        Throwable throwable     = context.getThrowable();
        String    statementName = context.getStatementName();
        String    statementCode = context.getEpl();
        
        log.warn("Esper engine {} experienced exception in query {}", engineName, statementName);
        log.warn("Esper engine exception", throwable);
    }
}

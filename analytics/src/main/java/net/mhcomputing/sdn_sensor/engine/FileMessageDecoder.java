package net.mhcomputing.sdn_sensor.engine;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.GZIPInputStream;

import net.mhcomputing.sdn_sensor.types.LogMessage;
import net.mhcomputing.sdn_sensor.utils.ByteBufferInputStream;
import net.mhcomputing.sdn_sensor.utils.Utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FileMessageDecoder extends LogMessageDecoder {
    private static Logger log =
        LoggerFactory.getLogger(FileMessageDecoder.class);
    
    public static final String TEST_LV_PATH = "src/test/resources/logs";
    public static final String LV_EXTENSION = "*.{jlv,jlv.gz}";
    
    protected String                    globExpr;
    protected PathMatcher               glob;
    
    protected ByteBuffer                lvBuffer;
    protected ByteBufferInputStream     lvStream;
    protected LogMessage                lmBuffer;
    protected List<String>              lvPaths;
    protected List<ReadableByteChannel> lvChannels;
    
    private class LvFileVisitor extends SimpleFileVisitor<Path> {
        @Override
        public FileVisitResult visitFile(Path path, BasicFileAttributes attrs) throws IOException {
            Path fileName = path.getFileName();
            String fileNameStr = fileName.toString();
            boolean isMatch = glob.matches(fileName);
            log.debug("visiting file {} isMatch {}", path, isMatch);
            
            if (!isMatch) return FileVisitResult.CONTINUE;
            
            lvPaths.add(path.toAbsolutePath().toString());
            if (fileNameStr.endsWith(".gz")) {
                GZIPInputStream gzipStream = new GZIPInputStream(new FileInputStream(path.toString()));
                ReadableByteChannel lvChannel = Channels.newChannel(gzipStream);
                lvChannels.add(lvChannel);
            }
            else {
                FileChannel lvChannel = FileChannel.open(path, StandardOpenOption.READ);
                lvChannels.add(lvChannel);
            }
            
            log.info("loaded LV file {}", path.toAbsolutePath().toString());
            
            return FileVisitResult.CONTINUE;
        }
        @Override
        public FileVisitResult visitFileFailed(Path path, IOException e) throws IOException {
            log.error("exception raised processing LV file " + path.toAbsolutePath().toString(), e);
            return FileVisitResult.CONTINUE;
        }
    }
    
    protected FileMessageDecoder() {
    }
    
    public FileMessageDecoder(String globExpr) {
        this.globExpr = globExpr;
        clear();
    }
        
    public void clearImpl() {
        try {
            if (Utils.isAnyValid(lvChannels, lvBuffer)) {
                close();
            }
            
            glob       = FileSystems.getDefault().getPathMatcher("glob:" + globExpr);
            lvBuffer   = LogMessageDecoder.createBuffer();
            lvStream   = LogMessageDecoder.createStream(this.lvBuffer);
            lvPaths    = new ArrayList<String>();
            lvChannels = new ArrayList<ReadableByteChannel>();
            index    = 0;
            
            log.info("loading files via glob {}", globExpr);
            Path   globPath     = Paths.get(globExpr);
            Path   globName     = globPath.getFileName();
            File   globFile     = globPath.toFile();
            Path   globDir      = globPath.getParent();
            String globNameExpr;
            
            boolean exists      = globFile.exists();
            boolean isFile      = globFile.isFile();
            boolean isDirectory = globFile.isDirectory();
            
            if (isFile || !exists) {
                globNameExpr = globName.toString();
            }
            else if (isDirectory) {
                globDir = globPath;
                globNameExpr = LV_EXTENSION;
                glob = FileSystems.getDefault().getPathMatcher("glob:" + globNameExpr);
            }
            else {
                String message = "path " + globName.toString() + " is neither file nor directory";
                log.error(message);
                throw new IllegalArgumentException(message);
            }
            
            Files.walkFileTree(globDir, new LvFileVisitor());
        }
        catch (Exception e) {
            log.error("could not initialize message decoder", e);
            throw new RuntimeException(e);
        }
    }
    
    public boolean hasNextImpl() {
        return index < lvChannels.size();
    }
    
    public LogMessage nextImpl() throws Exception {
        // XXX: add support for looping the input
        ReadableByteChannel current = lvChannels.get(index);
        LogMessage lm;
        
        lm = super.readLV(current, lvBuffer, lvStream);
        if (lm == null) {
            ++index;
            if (index < lvChannels.size()) {
                current = lvChannels.get(index);
                lm = super.readLV(current, lvBuffer, lvStream);
            }
        }
        
        return lm;
    }
    
    public void close() {
        int i = 0;
        try {
            for (/* nothing */; i < lvChannels.size(); ++i) {
                ReadableByteChannel lvChannel = lvChannels.get(i);
                lvChannel.close();
            }
        }
        catch (Exception e) {
            log.error("could not close LogMessageDecoder path " + lvPaths.get(i), e);
            throw new RuntimeException(e);
        }
    }
    
    public String getContext() {
        return "path: " + lvPaths.get(index) + " index: " + index + " current: " + current;
    }
    
    public static void main(String[] args) throws Throwable {
        FileMessageDecoder decoder = new FileMessageDecoder(TEST_LV_PATH);
        LogMessage         lastLm  = null;
        
        int i = 0;
        for (LogMessage lm : decoder) {
            if (i == 0) {
                Utils.wprintf(log, "lm id %d:\n%s", decoder.getCurrent(), lm);
            }
            else {
                Utils.dprintf(log, "lm id %d:\n%s", decoder.getCurrent(), lm);
            }
            ++i;
            if (lm != null) lastLm = lm;
        }
        
        Utils.wprintf(log, "lm id %d:\n%s", decoder.getCurrent(), lastLm);
        
        decoder.close();
    }
}

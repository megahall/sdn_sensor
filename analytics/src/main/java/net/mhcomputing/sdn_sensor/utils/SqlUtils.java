package net.mhcomputing.sdn_sensor.utils;

/*
 * Copyright 2002-2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import java.io.BufferedReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.common.base.Joiner;
import com.google.common.base.Splitter;

/**
 * A collection of JDBC related utility methods for
 * use in unit and integration testing scenarios.
 *
 * @author Thomas Risberg
 * @since 2.5.4
 */
public class SqlUtils {
    /**
     * Read a script from the BufferedReader and build a String containing the lines.
     * @param reader the {@code BufferedReader} containing the script to be processed
     * @return {@code String} containing the script lines
     * @throws IOException
     */
    public static String readScript(BufferedReader reader) throws IOException {
        String currentStatement = reader.readLine();
        StringBuilder scriptBuilder = new StringBuilder();
        while (currentStatement != null) {
            if (StringUtils.hasText(currentStatement)) {
                if (scriptBuilder.length() > 0) {
                    scriptBuilder.append('\n');
                }
                scriptBuilder.append(currentStatement);
            }
            currentStatement = reader.readLine();
        }
        return scriptBuilder.toString();
    }
    
    /**
     * Does the provided SQL script contain the specified delimiter?
     * @param script the SQL script
     * @param delim character delimiting each statement - typically a ';' character
     */
    public static boolean containsSqlScriptDelimiters(String script, char delim) {
        boolean inLiteral = false;
        char[] content = script.toCharArray();
        for (int i = 0; i < script.length(); i++) {
            if (content[i] == '\'') {
                inLiteral = !inLiteral;
            }
            if (content[i] == delim && !inLiteral) {
                return true;
            }
        }
        return false;
    }
    
    public static final Splitter SQL_SPLITTER = Splitter.on('\n').omitEmptyStrings();
    public static final Joiner   SQL_JOINER   = Joiner.on(' ').skipNulls();
    public static final Pattern  LINE_COMMENT = Pattern.compile("^\\s*--");
    public static final Pattern  FULL_COMMENT = Pattern.compile("^\\s*/\\*.*\\s*\\*/$");
    
    public static void addStatement(List<String> statements, StringBuilder sb) {
        boolean isUseful = false;
        
        Matcher commentMatcher = FULL_COMMENT.matcher(sb.toString().replace('\n', ' '));
        boolean isDisabled     = commentMatcher.lookingAt();
        if (isDisabled) {
            return;
        }
        
        List<String> lines = new ArrayList<String>(32);
        for (String line : SQL_SPLITTER.split(sb)) {
            commentMatcher = LINE_COMMENT.matcher(line);
            isDisabled     = commentMatcher.lookingAt();
            if (isDisabled) continue;
            lines.add(line);
            isUseful = true;
        }
        
        if (isUseful) {
            String statement = SQL_JOINER.join(lines);
            statements.add(statement);
        }
    }
    
    /**
     * Split an SQL script into separate statements delimited with the provided delimiter character. Each
     * individual statement will be added to the provided {@code List}.
     * @param script the SQL script
     * @param delim character delimiting each statement - typically a ';' character
     * @param statements the List that will contain the individual statements
     */
    public static void splitSqlScript(String script, char delim, List<String> statements) {
        StringBuilder sb = new StringBuilder();
        boolean inLiteral = false;
        char[] content = script.toCharArray();
        for (int i = 0; i < script.length(); i++) {
            if (content[i] == '\'') {
                inLiteral = !inLiteral;
            }
            if (content[i] == delim && !inLiteral) {
                if (sb.length() > 0) {
                    addStatement(statements, sb);
                    sb = new StringBuilder();
                }
            }
            else {
                sb.append(content[i]);
            }
        } 
        if (sb.length() > 0) {
            addStatement(statements, sb);
        }
    }
    
    public static void main(String[] args) {
        // TODO Auto-generated method stub
        
    }
}
package jcprofiler;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import javafx.util.Pair;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 *
* @author Petr Svenda
 */
public class PerfTests {
    final static byte[]         APPLET_AID = {(byte) 0xa0, (byte) 0x00, (byte) 0x00, (byte) 0x06, (byte) 0x17, (byte) 0x00, (byte) 0x4f, (byte) 0x97, (byte) 0xa2, (byte) 0xe9, (byte) 0x49, (byte) 0x01};
    static final byte           APPLET_CLA = (byte) 0xF0;
    static final byte[]         APDU_TRIGGER = {APPLET_CLA, 0x01, 0, 0, 0};
    static final byte[]         null; // TODO: set proper on-card cleaning command (if necessary). Set to null if not necessary  
    static final String         CARD_NAME = "noCardNameGiven";              // TODO: fill name of your card; 

    static final byte           INS_PERF_SETTRAPID = (byte) 0xf5;
    static byte[]               APDU_SETTRAPID = {APPLET_CLA, INS_PERF_SETTRAPID, 0, 0, 2, 0, 0};
    static final byte[]         APDU_SETTRAPID_NONE = {APPLET_CLA, INS_PERF_SETTRAPID, 0, 0, 2, 0, 0};
    
    class PerfConfig {
        public String cardName = "noCardNameGiven";
        public FileOutputStream perfFile = null;
        public ArrayList<Pair<String, Long>> perfResultsSingleOp = new ArrayList<>();
        public ArrayList<String> perfResultsSubparts = new ArrayList<>();
        public HashMap<Short, Pair<Short, Long>> perfResultsSubpartsRaw = new HashMap<>(); // hashmap with key being perf trap id, folowed by pair <prevTrapID, elapsedTimeFromPrev>
        public boolean bMeasurePerf = true;
        public short[] perfStops = null;
        public short perfStopComplete = -1;
        public ArrayList<String> failedPerfTraps = new ArrayList<>();
    }    

    PerfTests() {
        buildPerfMapping();        
    }
    
    void RunPerformanceTests(int numRepeats, boolean MODIFY_SOURCE_FILES_BY_PERF) throws Exception {
        PerfConfig cfg = new PerfConfig();
        String experimentID = String.format("%d", System.currentTimeMillis());
        cfg.perfFile = new FileOutputStream(String.format("OC_PERF_log_%s.csv", experimentID));

        try {
            CardManager cardMngr = new CardManager();
            System.out.println("Connecting to card...");
            cardMngr.ConnectToCard(APPLET_AID);
            System.out.println(" Done.");

            cardMngr.transmit(new CommandAPDU(APDU_SETTRAPID_NONE)); // erase any previous performance stop 
            if (APDU_CLEANUP != null) { // reset if required
                cardMngr.transmit(new CommandAPDU(APDU_CLEANUP));         
            }

            System.out.println("\n-------------- Performance profiling start --------------\n\n");

//### PLACEHOLDER PERFTRAPS INIT

            short[] PERFTRAPS_methodName = {PMC.TRAP_methodName_1, PMC.TRAP_methodName_2, PMC.TRAP_methodName_3, PMC.TRAP_methodName_4, PMC.TRAP_methodName_5, PMC.TRAP_methodName_6, PMC.TRAP_methodName_7, PMC.TRAP_methodName_8, PMC.TRAP_methodName_9, PMC.TRAP_methodName_10, PMC.TRAP_methodName_11, PMC.TRAP_methodName_12, PMC.TRAP_methodName_13, PMC.TRAP_methodName_14, PMC.TRAP_methodName_15, PMC.TRAP_methodName_16, PMC.TRAP_methodName_17, PMC.TRAP_methodName_18, PMC.TRAP_methodName_19, PMC.TRAP_methodName_20, PMC.TRAP_methodName_21, PMC.TRAP_methodName_22, PMC.TRAP_methodName_23, PMC.TRAP_methodName_24, PMC.TRAP_methodName_25, PMC.TRAP_methodName_26, PMC.TRAP_methodName_27, PMC.TRAP_methodName_28, PMC.TRAP_methodName_29, PMC.TRAP_methodName_30, PMC.TRAP_methodName_31, PMC.TRAP_methodName_32, PMC.TRAP_methodName_33, PMC.TRAP_methodName_34, PMC.TRAP_methodName_35, PMC.TRAP_methodName_36, PMC.TRAP_methodName_37, PMC.TRAP_methodName_38, PMC.TRAP_methodName_39, PMC.TRAP_methodName_40, PMC.TRAP_methodName_41, PMC.TRAP_methodName_42, PMC.TRAP_methodName_43, PMC.TRAP_methodName_44, PMC.TRAP_methodName_45, PMC.TRAP_methodName_46, PMC.TRAP_methodName_47, PMC.TRAP_methodName_48, PMC.TRAP_methodName_49, PMC.TRAP_methodName_50, PMC.TRAP_methodName_51, PMC.TRAP_methodName_COMPLETE};
            cfg.perfStops = PERFTRAPS_methodName;
            cfg.perfStopComplete = PMC.TRAP_methodName_COMPLETE;
            for (int repeat = 0; repeat < numRepeats; repeat++) {
                CommandAPDU cmd = new CommandAPDU(APDU_TRIGGER);
                PerfAnalyzeCommand("insert nice name", cmd, cardMngr, cfg);
            }

            System.out.println("\n-------------- Performance profiling finished --------------\n\n");
            System.out.print("Disconnecting from card...");
            cardMngr.DisconnectFromCard();
            System.out.println(" Done.");
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        if (cfg.failedPerfTraps.size() > 0) {
            System.out.println("#########################");
            System.out.println("!!! SOME PERFORMANCE TRAPS NOT REACHED !!!");
            System.out.println("#########################");
            for (String trap : cfg.failedPerfTraps) {
                System.out.println(trap);
            }
        } else {
            System.out.println("##########################");
            System.out.println("ALL PERFORMANCE TRAPS REACHED CORRECTLY");
            System.out.println("##########################");
        }       
        
        // Save performance traps into single file
        String perfFileName = String.format("TRAP_RAW_%s.csv", experimentID);
        SavePerformanceResults(cfg.perfResultsSubpartsRaw, perfFileName);
                
        // If required, modification of source code files is attempted
        if (MODIFY_SOURCE_FILES_BY_PERF) {
            String dirPath = "..\\Profiler_applet\\";
            System.out.println(String.format("INFO: going to insert profiled info into files in '%s' directory", dirPath));
            InsertPerfInfoIntoFiles(dirPath, cfg.cardName, experimentID, cfg.perfResultsSubpartsRaw);
        }
    }    
    
    static void SavePerformanceResults(HashMap<Short, Pair<Short, Long>> perfResultsSubpartsRaw, String fileName) throws FileNotFoundException, IOException {
        // Save performance traps into single file
        FileOutputStream perfLog = new FileOutputStream(fileName);
        String output = "trapID, previous trapID, time difference between trapID and previous trapID (ms)\n";
        perfLog.write(output.getBytes());
        for (Short perfID : perfResultsSubpartsRaw.keySet()) {
            output = String.format("%d, %d, %d\n", perfID, perfResultsSubpartsRaw.get(perfID).getKey(), perfResultsSubpartsRaw.get(perfID).getValue());
            perfLog.write(output.getBytes());
        }
        perfLog.close();
    }
    
    static void LoadPerformanceResults(String fileName, HashMap<Short, Pair<Short, Long>> perfResultsSubpartsRaw) throws FileNotFoundException, IOException {
        BufferedReader br = new BufferedReader(new FileReader(fileName));
        String strLine;
        while ((strLine = br.readLine()) != null) {
            if (strLine.contains("trapID,")) {
                // skip header line
            }
            else {
                String[] cols = strLine.split(",");
                Short perfID = Short.parseShort(cols[0].trim());
                Short prevPerfID = Short.parseShort(cols[1].trim());
                Long elapsed = Long.parseLong(cols[2].trim());
                
                perfResultsSubpartsRaw.put(perfID, new Pair(prevPerfID, elapsed));
            }
        }
        br.close();
    }    

    public static byte[] shortToByteArray(int s) {
        return new byte[]{(byte) ((s & 0xFF00) >> 8), (byte) (s & 0x00FF)};
    }    
    long PerfAnalyzeCommand(String operationName, CommandAPDU cmd, CardManager cardMngr, PerfConfig cfg) throws CardException, IOException {
        System.out.println(operationName);
        short prevPerfStop = PMC.PERF_START;
        long prevTransmitTime = 0;
        long lastFromPrevTime = 0;
        try {
            for (short trapID : cfg.perfStops) {
                System.arraycopy(shortToByteArray(trapID), 0, APDU_SETTRAPID, CardManager.OFFSET_CDATA, 2); // set required stop condition
                String operationNamePerf = String.format("%s_%s", operationName, getPerfStopName(trapID));
                cardMngr.transmit(new CommandAPDU(APDU_SETTRAPID)); // set performance trap
                ResponseAPDU response = cardMngr.transmit(cmd); // execute target operation
                boolean bFailedToReachTrap = false;
                if (trapID != cfg.perfStopComplete) { // Check expected error to be equal performance trap
                    if (response.getSW() != (trapID & 0xffff)) {
                        // we have not reached expected performance trap
                        cfg.failedPerfTraps.add(getPerfStopName(trapID));
                        bFailedToReachTrap = true;
                    }
                }
                writePerfLog(operationNamePerf, response.getSW() == (CardManager.SW_NO_ERROR & 0xffff), cardMngr.m_lastTransmitTime, cfg.perfResultsSingleOp, cfg.perfFile);
                long fromPrevTime = cardMngr.m_lastTransmitTime - prevTransmitTime;
                if (bFailedToReachTrap) {
                    cfg.perfResultsSubparts.add(String.format("[%s-%s], \tfailed to reach after %d ms (0x%x)", getPerfStopName(prevPerfStop), getPerfStopName(trapID), cardMngr.m_lastTransmitTime, response.getSW()));
                }
                else {
                    cfg.perfResultsSubparts.add(String.format("[%s-%s], \t%d ms", getPerfStopName(prevPerfStop), getPerfStopName(trapID), fromPrevTime));
                    cfg.perfResultsSubpartsRaw.put(trapID, new Pair(prevPerfStop, fromPrevTime)); 
                    lastFromPrevTime = fromPrevTime;
                }

                prevPerfStop = trapID;
                prevTransmitTime = cardMngr.m_lastTransmitTime;

                if (APDU_CLEANUP != null) {
                    cardMngr.transmit(new CommandAPDU(APDU_CLEANUP)); // free memory after command
                }
            }
        }
        catch (Exception e) {
            // Print what we have measured so far
            for (String res : cfg.perfResultsSubparts) {
                System.out.println(res);
            }
            throw e;
        }
        // Print measured performance info
        for (String res : cfg.perfResultsSubparts) {
            System.out.println(res);
        }
        
        return lastFromPrevTime;
    }    
    
    
    static void writePerfLog(String operationName, boolean bResult, Long time, ArrayList<Pair<String, Long>> perfResults, FileOutputStream perfFile) throws IOException {
        perfResults.add(new Pair(operationName, time));
        perfFile.write(String.format("%s,%d,%s\n", operationName, time, bResult).getBytes());
        perfFile.flush();
    }
    
    
    static void InsertPerfInfoIntoFiles(String basePath, String cardName, String experimentID, HashMap<Short, Pair<Short, Long>> perfResultsSubpartsRaw) throws FileNotFoundException, IOException {
        File dir = new File(basePath);
        String[] filesArray = dir.list();
        if ((filesArray != null) && (dir.isDirectory() == true)) {
            // make subdir for results
            String outputDir = String.format("%s\\perf\\%s\\", basePath, experimentID);
            new File(outputDir).mkdirs();

            for (String fileName : filesArray) {
                File dir2 = new File(basePath + fileName);
                if (!dir2.isDirectory()) {
                    InsertPerfInfoIntoFile(String.format("%s\\%s", basePath, fileName), cardName, experimentID, outputDir, perfResultsSubpartsRaw);
                }
            }
        }
    }
    
    static final String PERF_TRAP_CALL = "PM.check(PMC.";
    static final String PERF_TRAP_CALL_END = ");";
    static void InsertPerfInfoIntoFile(String filePath, String cardName, String experimentID, String outputDir, HashMap<Short, Pair<Short, Long>> perfResultsSubpartsRaw) throws FileNotFoundException, IOException {
        try {
            BufferedReader br = new BufferedReader(new FileReader(filePath));
            String basePath = filePath.substring(0, filePath.lastIndexOf("\\"));
            String fileName = filePath.substring(filePath.lastIndexOf("\\"));
            
            String fileNamePerf = String.format("%s\\%s", outputDir, fileName);
            FileOutputStream fileOut = new FileOutputStream(fileNamePerf);
            String strLine;
            String resLine;
            // For every line of program try to find perfromance trap. If found and perf. is available, then insert comment into code
            while ((strLine = br.readLine()) != null) {
                
                if (strLine.contains(PERF_TRAP_CALL)) {
                    int trapStart = strLine.indexOf(PERF_TRAP_CALL);
                    int trapEnd = strLine.indexOf(PERF_TRAP_CALL_END);
                    // We have perf. trap, now check if we also corresponding measurement
                    String perfTrapName = (String) strLine.substring(trapStart + PERF_TRAP_CALL.length(), trapEnd);
                    short perfID = getPerfStopFromName(perfTrapName);
                    
                    if (perfResultsSubpartsRaw.containsKey(perfID)) {
                        // We have measurement for this trap, add into comment section
                        resLine = String.format("%s // %d ms (%s,%s) %s", (String) strLine.substring(0, trapEnd + PERF_TRAP_CALL_END.length()), perfResultsSubpartsRaw.get(perfID).getValue(), cardName, experimentID, (String) strLine.subSequence(trapEnd + PERF_TRAP_CALL_END.length(), strLine.length()));
                    }
                    else {
                        resLine = strLine;
                    }
                }
                else {
                    resLine = strLine;
                }
                resLine += "\n";
                fileOut.write(resLine.getBytes());
            }
            
            fileOut.close();
        }
        catch(Exception e) {
            System.out.println(String.format("Failed to transform file %s ", filePath) + e);
        }
    }
    
    public static HashMap<Short, String> PERF_TRAPS_MAPPING = new HashMap<>();
    public static void buildPerfMapping() {
        PERF_TRAPS_MAPPING.put(PMC.PERF_START, "PERF_START");

//### PLACEHOLDER PMC MAPPINGS

        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_1, "TRAP_methodName_1");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_2, "TRAP_methodName_2");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_3, "TRAP_methodName_3");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_4, "TRAP_methodName_4");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_5, "TRAP_methodName_5");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_6, "TRAP_methodName_6");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_7, "TRAP_methodName_7");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_8, "TRAP_methodName_8");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_9, "TRAP_methodName_9");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_10, "TRAP_methodName_10");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_11, "TRAP_methodName_11");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_12, "TRAP_methodName_12");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_13, "TRAP_methodName_13");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_14, "TRAP_methodName_14");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_15, "TRAP_methodName_15");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_16, "TRAP_methodName_16");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_17, "TRAP_methodName_17");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_18, "TRAP_methodName_18");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_19, "TRAP_methodName_19");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_20, "TRAP_methodName_20");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_21, "TRAP_methodName_21");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_22, "TRAP_methodName_22");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_23, "TRAP_methodName_23");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_24, "TRAP_methodName_24");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_25, "TRAP_methodName_25");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_26, "TRAP_methodName_26");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_27, "TRAP_methodName_27");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_28, "TRAP_methodName_28");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_29, "TRAP_methodName_29");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_30, "TRAP_methodName_30");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_31, "TRAP_methodName_31");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_32, "TRAP_methodName_32");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_33, "TRAP_methodName_33");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_34, "TRAP_methodName_34");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_35, "TRAP_methodName_35");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_36, "TRAP_methodName_36");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_37, "TRAP_methodName_37");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_38, "TRAP_methodName_38");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_39, "TRAP_methodName_39");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_40, "TRAP_methodName_40");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_41, "TRAP_methodName_41");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_42, "TRAP_methodName_42");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_43, "TRAP_methodName_43");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_44, "TRAP_methodName_44");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_45, "TRAP_methodName_45");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_46, "TRAP_methodName_46");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_47, "TRAP_methodName_47");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_48, "TRAP_methodName_48");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_49, "TRAP_methodName_49");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_50, "TRAP_methodName_50");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_51, "TRAP_methodName_51");
        PERF_TRAPS_MAPPING.put(PMC.TRAP_methodName_COMPLETE, "TRAP_methodName_COMPLETE");

        
    }

    public static String getPerfStopName(short stopID) {
        if (PERF_TRAPS_MAPPING.containsKey(stopID)) {
            return PERF_TRAPS_MAPPING.get(stopID);
        } else {
            assert (false);
            return "PERF_UNDEFINED";
        }
    }

    public static short getPerfStopFromName(String stopName) {
        for (Short stopID : PERF_TRAPS_MAPPING.keySet()) {
            if (PERF_TRAPS_MAPPING.get(stopID).equalsIgnoreCase(stopName)) {
                return stopID;
            }
        }
        assert (false);
        return PMC.TRAP_UNDEFINED;
    }
}

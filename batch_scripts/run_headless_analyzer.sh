/home/liger/LIGERLabs/REtools/ghidra_9.2.4_PUBLIC/support/analyzeHeadless \
/home/liger/ghidra/projects/crackme crackme \
-import /home/liger/CM0588/crackme-bin-linux/crackme0x00 \
-scriptPath /home/liger/GhidraProgramMeasures/ghidra_scripts \
-scriptPath /home/liger/GhidraProgramMeasures/src/main/java \
-postScript ProgramMeasuresScript.java analysis=halstead analyze-function=main export=json export-path=/home/liger/Desktop/lol.json \
-overwrite

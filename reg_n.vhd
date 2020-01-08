
-------------------------------------------------------------------------------
--! @file       reg_n.vhd
--! @author     William Diehl
--! @brief      
--! @date       9 Sep 2016
-------------------------------------------------------------------------------

LIBRARY ieee;
USE ieee.std_logic_1164.all;

ENTITY reg_n IS
	GENERIC (N:INTEGER :=16);
	PORT(D : IN STD_LOGIC_VECTOR(N-1 DOWNTO 0);
	     CLK  : IN STD_LOGIC;
             EN   : IN STD_LOGIC;
	     Q    : OUT STD_LOGIC_VECTOR(N-1 DOWNTO 0):=(OTHERS=>'0'));
END reg_n;

ARCHITECTURE behavioral OF reg_n IS
BEGIN
	PROCESS (CLK)
        BEGIN
            
            IF rising_edge(CLK) THEN
               IF (EN = '1') THEN
                    Q <= D;
               END IF;
	    END IF;
        END PROCESS;
END behavioral;

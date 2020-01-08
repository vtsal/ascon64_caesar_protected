--------------------------------------------------------------------------------
--! @File        : Reg.vhd
--! @Brief       : 1-bit register
--!   ______   ________  _______    ______  
--!  /      \ /        |/       \  /      \ 
--! /$$$$$$  |$$$$$$$$/ $$$$$$$  |/$$$$$$  |
--! $$ |  $$/ $$ |__    $$ |__$$ |$$ | _$$/ 
--! $$ |      $$    |   $$    $$< $$ |/    |
--! $$ |   __ $$$$$/    $$$$$$$  |$$ |$$$$ |
--! $$ \__/  |$$ |_____ $$ |  $$ |$$ \__$$ |
--! $$    $$/ $$       |$$ |  $$ |$$    $$/ 
--!  $$$$$$/  $$$$$$$$/ $$/   $$/  $$$$$$/  
--!
--! @Author      : Panasayya Yalla
--! @Copyright   : Copyright© 2016 Cryptographic Engineering Research Group
--!                ECE Department, George Mason University Fairfax, VA, U.S.A.
--!                All rights Reserved.
--! @license    This project is released under the GNU Public License.          
--!             The license and distribution terms for this file may be         
--!             found in the file LICENSE in this distribution or at            
--!             http://www.gnu.org/licenses/gpl-3.0.txt                         
--! @note       This is publicly available encryption source code that falls    
--!             under the License Exception TSU (Technology and software-       
--!             —unrestricted)                                                  
--------------------------------------------------------------------------------
--! Description
--! clk          : Clock
--! en           : Enable
--! din          : register input
--! dout         : register output
--------------------------------------------------------------------------------

library ieee;
use ieee.std_logic_1164.all;


entity Reg is 
    port    (
                clk : in  std_logic;
                ena : in  std_logic;
                din : in  std_logic;
                dout: out std_logic
             );
end Reg;

architecture Reg of Reg is 
    signal qnext:std_logic;
begin   
    
reg:    process(clk)
        begin
            if rising_edge(clk) then 
                if ena ='1' then
                    qnext <= din; 
                end if;
            end if; 
        end process;
      dout<=qnext;
  
end Reg;

-------------------------------------------------------------------------------
--! @file       AEAD_Wrapper.vhd
--! @brief      5-bit wrapper for AEAD.vhd
--! @project    CAESAR Candidate Evaluation
--! @author     Ekawat (ice) Homsirikamol
--! @copyright  Copyright (c) 2015 Cryptographic Engineering Research Group
--!             ECE Department, George Mason University Fairfax, VA, U.S.A.
--!             All rights Reserved.
--! @license    This project is released under the GNU Public License.
--!             The license and distribution terms for this file may be
--!             found in the file LICENSE in this distribution or at
--!             http://www.gnu.org/licenses/gpl-3.0.txt
--! @note       This is publicly available encryption source code that falls
--!             under the License Exception TSU (Technology and software-
--!             —unrestricted)
-------------------------------------------------------------------------------

library ieee;
use ieee.std_logic_1164.all;

entity AEAD_Wrapper is
    generic (
        G_W             : integer := 8;
        G_SW            : integer := 8;
		  G_RW				: integer := 192
    );
    port (
        --! Global signals
        clk             : in  std_logic;
        rst             : in  std_logic;
		  pdi_valid       : in  std_logic;
		  sdi_valid       : in  std_logic;
		  rdi_valid       : in  std_logic;
		  do_ready        : in  std_logic;
		  
		  pdi_ready       : out  std_logic;
		  sdi_ready       : out  std_logic;
		  rdi_ready       : out  std_logic;
		  do_valid        : out  std_logic;

        --! SERDES signals
        sin             : in  std_logic;
        ssel            : in  std_logic;
        sout            : out std_logic
    );
end entity AEAD_Wrapper;

architecture structure of AEAD_Wrapper is
    signal sipo         : std_logic_vector(2 * G_W + 2 * G_SW + G_RW      -1 downto 0);
    signal piso         : std_logic_vector(2 * G_W            -1 downto 0);
    signal piso_data    : std_logic_vector(2 * G_W            -1 downto 0);
begin
    process(clk)
    begin
        if rising_edge(clk) then
            sipo <= sin & sipo(sipo'high downto 1);
            if (ssel = '1') then
                piso <= piso_data;
            else
                piso <= '0' & piso(piso'high downto 1);
            end if;
        end if;
    end process;
    sout <= piso(0);

    u_aead:
    entity work.AEAD(structure)
    generic map (
        G_W                     => G_W                          ,
        G_SW                    => G_SW,
		  G_RW						  => G_RW
		  
    )
    port map (
        clk                     => clk                          ,
        rst                     => rst                          ,
		  pdi_valid               => pdi_valid,
		  sdi_valid               => sdi_valid,
		  rdi_valid               => rdi_valid,
		  do_valid                => do_valid,
		  pdi_ready               => pdi_ready,
		  sdi_ready               => sdi_ready,
		  rdi_ready               => rdi_ready,
		  do_ready                => do_ready,

        --! Input signals
        pdi_data_a                => sipo(       G_W-1 downto   0),
        pdi_data_b                => sipo(       2* G_W-1 downto   G_W),

        sdi_data_a                => sipo(  G_SW+ 2 * G_W-1 downto 2* G_W),
        sdi_data_b                => sipo(  2*G_SW+2*G_W-1 downto 2* G_W + G_SW),
		  
        rdi_data                => sipo(  G_RW + 2*G_SW + 2*G_W-1 downto 2*G_W + 2*G_SW),

        --! Output signals
        do_data_a                 => piso_data(  G_W-1 downto   0),
        do_data_b                 => piso_data(  2*G_W-1 downto   G_W)
    );
end structure;
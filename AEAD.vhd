--------------------------------------------------------------------------------
--! @File        : AEAD.vhd (CAESAR API for Lightweight)
--! @Brief       : AEAD top level file
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
--! @Author      : Panasayya Yalla & Ekawat (ice) Homsirikamol
--! @Copyright   : Copyright © 2016 Cryptographic Engineering Research Group    
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
--! 
--! 
--! 
--! 
--! 
--! 
--------------------------------------------------------------------------------

library ieee;
use ieee.std_logic_1164.all;
use work.Design_pkg.all;
use work.CAESAR_LWAPI_pkg.all;

entity AEAD is
    generic (
        G_W             : integer := PW;
        G_SW            : integer := SW;
		  G_RW            : integer := RW;
        --! Reset behavior
        G_ASYNC_RSTN    : boolean := False;  --! Async active low reset        
        --! Block size (bits)
        G_ABLK_SIZE     : integer := G_DBLK_SIZE;   --! Associated data
        G_DBLK_SIZE     : integer := G_DBLK_SIZE;   --! Data
        G_KEY_SIZE      : integer := G_KEY_SIZE;    --! Key
        G_TAG_SIZE      : integer := G_TAG_SIZE     --! Tag        
    );
    port (
        --! Global ports
        clk             : in  std_logic;
        rst             : in  std_logic;
        --! Publica data ports
        pdi_data_a        : in  std_logic_vector(PW             -1 downto 0);
        pdi_data_b        : in  std_logic_vector(PW             -1 downto 0);
        pdi_valid       : in  std_logic;
        pdi_ready       : out std_logic;
        --! Secret data ports
        sdi_data_a        : in  std_logic_vector(SW             -1 downto 0);
        sdi_data_b        : in  std_logic_vector(SW             -1 downto 0);
        sdi_valid       : in  std_logic;
        sdi_ready       : out std_logic;
        --! Data out ports
        do_data_a         : out std_logic_vector(PW             -1 downto 0);
        do_data_b         : out std_logic_vector(PW             -1 downto 0);
        do_ready        : in  std_logic;
        do_valid        : out std_logic;
		  --! random inputs
		  rdi_data         : in std_logic_vector(RW - 1 downto 0);
		  rdi_valid			 : in std_logic;
		  rdi_ready        : out std_logic
    );
end AEAD;

architecture structure of AEAD is
    --==========================================================================
    --!Cipher
    --==========================================================================
    ------!Pre-Processor to Cipher (Key PISO)
    signal key_cipher_in_a          : std_logic_vector(SW           -1 downto 0);
    signal key_cipher_in_b          : std_logic_vector(SW           -1 downto 0);
    signal key_valid_cipher_in      : std_logic;                    
    signal key_ready_cipher_in      : std_logic;                    
    ------!Pre-Processor to Cipher (DATA PISO)                                                             
    signal bdi_cipher_in_a          : std_logic_vector(PW           -1 downto 0);
    signal bdi_cipher_in_b          : std_logic_vector(PW           -1 downto 0);
    signal bdi_valid_cipher_in      : std_logic;
    signal bdi_ready_cipher_in      : std_logic;
    --
    signal bdi_partial_cipher_in    : std_logic;
    signal bdi_pad_loc_cipher_in    : std_logic_vector(PWdiv8       -1 downto 0);
    signal bdi_valid_bytes_cipher_in: std_logic_vector(PWdiv8       -1 downto 0);
    signal bdi_size_cipher_in       : std_logic_vector(3            -1 downto 0);
    signal bdi_eot_cipher_in        : std_logic;
    signal bdi_eoi_cipher_in        : std_logic;
    signal bdi_type_cipher_in       : std_logic_vector(4            -1 downto 0);
    signal decrypt_cipher_in        : std_logic;
    signal key_update_cipher_in     : std_logic;
    ------!Cipher(DATA SIPO) to Post-Processor
    signal bdo_cipher_out_a         : std_logic_vector(PW           -1 downto 0);
    signal bdo_cipher_out_b         : std_logic_vector(PW           -1 downto 0);
    signal bdo_valid_cipher_out     : std_logic;
    signal bdo_ready_cipher_out     : std_logic;
    ------!Cipher to Post-Processor
    signal end_of_block_cipher_out  : std_logic;
    signal bdo_size_cipher_out      : std_logic_vector(3           -1 downto 0);
    signal bdi_valid_bytes_cipher_out:std_logic_vector(PWdiv8      -1 downto 0);
    signal bdo_type_cipher_out      :std_logic_vector(4            -1 downto 0);
    signal decrypt_cipher_out       : std_logic;
    signal msg_auth_valid           : std_logic;
    signal msg_auth_ready           : std_logic;
    signal msg_auth                 : std_logic;
    signal done                     : std_logic;
    --==========================================================================
    
    --==========================================================================
    --!FIFO
    --==========================================================================
    ------!Pre-Processor to FIFO
    signal cmd_FIFO_in              : std_logic_vector(PW             -1 downto 0);
    signal cmd_valid_FIFO_in        : std_logic;
    signal cmd_ready_FIFO_in        : std_logic;
    ------!FIFO to Post_Processor
    signal cmd_FIFO_out             : std_logic_vector(PW             -1 downto 0);
    signal cmd_valid_FIFO_out       : std_logic;
    signal cmd_ready_FIFO_out       : std_logic;
    --==========================================================================
begin
    Inst_PreProcessor: entity work.PreProcessor_mod(PreProcessor)
        PORT MAP(
                clk             => clk                                     ,
                rst             => rst                                     ,
                pdi_data_a      => pdi_data_a                              ,
                pdi_data_b      => pdi_data_b                              ,
                pdi_valid       => pdi_valid                               ,
                pdi_ready       => pdi_ready                               ,
                sdi_data_a      => sdi_data_a                              ,
                sdi_data_b      => sdi_data_b                              ,
                sdi_valid       => sdi_valid                               ,
                sdi_ready       => sdi_ready                               ,
                key_a           => key_cipher_in_a                         ,      
                key_b           => key_cipher_in_b                         ,
                key_valid       => key_valid_cipher_in                     ,
                key_ready       => key_ready_cipher_in                     ,
                bdi_a           => bdi_cipher_in_a                         ,
                bdi_b           => bdi_cipher_in_b                         ,
                bdi_valid       => bdi_valid_cipher_in                     ,
                bdi_ready       => bdi_ready_cipher_in                     ,
                bdi_partial     => bdi_partial_cipher_in                   ,
                bdi_pad_loc     => bdi_pad_loc_cipher_in                   ,
                bdi_valid_bytes => bdi_valid_bytes_cipher_in               ,
                bdi_size        => bdi_size_cipher_in                      ,
                bdi_eot         => bdi_eot_cipher_in                       ,
                bdi_eoi         => bdi_eoi_cipher_in                       ,
                bdi_type        => bdi_type_cipher_in                      ,
                decrypt         => decrypt_cipher_in                       ,
                key_update      => key_update_cipher_in                    ,
                --done            => done                                    ,
                cmd             => cmd_FIFO_in                             ,
                cmd_valid       => cmd_valid_FIFO_in                       ,
                cmd_ready       => cmd_ready_FIFO_in
            );
    Inst_Cipher: entity work.CipherCore_8bit(structural) 

        PORT MAP(
                clk             => clk                                     ,
                rst             => rst                                     ,
                keya            => key_cipher_in_a                         ,
                keyb            => key_cipher_in_b                         ,
                key_valid       => key_valid_cipher_in                     ,
                key_ready       => key_ready_cipher_in                     ,
                bdia            => bdi_cipher_in_a                         ,
                bdib            => bdi_cipher_in_b                         ,
					 m					  => rdi_data,
                bdi_valid       => bdi_valid_cipher_in                     ,
                bdi_ready       => bdi_ready_cipher_in                     ,
                bdi_partial     => bdi_partial_cipher_in                   ,
                --bdi_pad_loc     => bdi_pad_loc_cipher_in                   ,
                bdi_valid_bytes => bdi_valid_bytes_cipher_in               ,
                bdi_size        => bdi_size_cipher_in                      ,
                bdi_eot         => bdi_eot_cipher_in                       ,
                bdi_eoi         => bdi_eoi_cipher_in                       ,
                bdi_type        => bdi_type_cipher_in                      ,
                decrypt         => decrypt_cipher_in                       ,
                key_update      => key_update_cipher_in                    ,
                bdoa            => bdo_cipher_out_a                        ,
                bdob            => bdo_cipher_out_b                        ,
                bdo_valid       => bdo_valid_cipher_out                    ,
                bdo_ready       => bdo_ready_cipher_out                    ,
                --bdo_type        => bdo_type_cipher_out                     , -- not sure
                --bdo_valid_bytes => bdi_valid_bytes_cipher_out              ,
                end_of_block    => end_of_block_cipher_out                 , -- not sure
                --done            => done                                    ,
                msg_auth_valid  => msg_auth_valid                          ,
                msg_auth_ready  => msg_auth_ready                          ,
                msg_auth        => msg_auth                             
					 );
    Inst_PostProcessor: entity work.PostProcessor_mod(PostProcessor) 
        GENERIC MAP ( G_TAG_SIZE => G_TAG_SIZE )
        PORT MAP(
                clk             => clk                                     ,
                rst             => rst                                     ,
                bdo_a           => bdo_cipher_out_a                        ,
                bdo_b           => bdo_cipher_out_b                        ,
                bdo_valid       => bdo_valid_cipher_out                    ,
                bdo_ready       => bdo_ready_cipher_out                    ,
                end_of_block    => end_of_block_cipher_out                 ,
                bdo_type        => bdo_type_cipher_out                     ,
                cmd             => cmd_FIFO_out                            ,
                cmd_valid       => cmd_valid_FIFO_out                      ,
                cmd_ready       => cmd_ready_FIFO_out                      ,
                do_data_a       => do_data_a                               ,
                do_data_b       => do_data_b                               ,
                do_valid        => do_valid                                ,
                do_ready        => do_ready                                ,
                bdo_valid_bytes => bdi_valid_bytes_cipher_out              ,
                msg_auth_valid  => msg_auth_valid                          ,
                msg_auth_ready  => msg_auth_ready                          ,
                msg_auth        => msg_auth                                
            );
    Inst_fwft_fifo: entity work.fwft_fifo(structure) 
        generic map (
                G_W             => PW                                      ,
                G_LOG2DEPTH     => 2                                      ,
                G_ASYNC_RSTN    => G_ASYNC_RSTN
            )
        PORT MAP(
                clk             => clk,
                rst             => rst,
                din             => cmd_FIFO_in,
                din_valid       => cmd_valid_FIFO_in,
                din_ready       => cmd_ready_FIFO_in,
                dout            => cmd_FIFO_out,
                dout_valid      => cmd_valid_FIFO_out,
                dout_ready      => cmd_ready_FIFO_out
            );
        


end structure;
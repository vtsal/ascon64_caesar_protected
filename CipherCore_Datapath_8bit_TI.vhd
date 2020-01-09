-------------------------------------------------------------------------------
--! @file       CipherCore_Datapath_8bit.vhd Ver 1.1 (TI protected)
--! @author     William Diehl 
--! @brief      Datapath for ASCON128 in LW interface with PW=SW=8
--! @version    04-03-2018     
-------------------------------------------------------------------------------

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;
use IEEE.STD_LOGIC_UNSIGNED.ALL; -- Added by Behnaz
use work.AEAD_pkg.all;
use work.design_pkg.all;

entity CipherCore_Datapath_8bit is
    generic (
		  G_NPUB_SIZE       : integer := 128; -- default for aes-gcm
		  G_DBLK_SIZE       : integer := 64; --default for aes-gcm
		  G_KEY_SIZE		: integer := 128 --default for aes-gcm
    );
    port    (
        clk                 : in  std_logic;
        rst                 : in  std_logic;

        --! Input
        bdia, bdib          : in  std_logic_vector(8 - 1 downto 0):=(others => '0');
        keya, keyb          : in  std_logic_vector(8 - 1 downto 0);
  	    ld_ctr			    : in  std_logic_vector(3 downto 0);
		 m                  : in std_logic_vector(RW  -1  downto 0);

        --! Control
        decrypt             : in std_logic;
        decrypt_last        : in std_logic;        
        rc					: in std_logic_vector(7 downto 0);
		perm_start          : in std_logic;
		perm_reset          : in std_logic;
		perm_done           : out std_logic;
        en_key              : in  std_logic;
        en_bdi              : in  std_logic:='0';
		clr_bdi             : in std_logic;
		en_bdo              : in  std_logic;
        ld_bdo			    : in  std_logic;
		bank0_op1_sel       : in  std_logic_vector(1 downto 0);
		bank0_op2_sel       : in  std_logic_vector(1 downto 0);

		op1_sel           : in std_logic_vector(1 downto 0);
		op2_sel           : in std_logic_vector(1 downto 0);
        key_sel			  : in std_logic;
		bank0_en          : in std_logic;
		bank1_en          : in std_logic;
		bank2_en          : in std_logic;
		sel_tag           : in std_logic;
        --! Output
        bdoa, bdob        : out std_logic_vector(8 - 1 downto 0);
--		msg_auth_valid	  : out std_logic;
        msg_auth	      : out std_logic;
		--state_debug		    : out std_logic_vector(11 downto 0)
		
		-- Added by Behnaz ------------------------------------
        --=====================================================
        raReg_en       : in std_logic;
        rbReg_en       : in std_logic;
        c1a_en         : in std_logic;
        c2a_en         : in std_logic;
        c1b_en         : in std_logic;
        c2b_en         : in std_logic;
        d1a_en         : in std_logic;
        d2a_en         : in std_logic;
        d1b_en         : in std_logic;
        d2b_en         : in std_logic
        --=====================================================
    );

end entity CipherCore_Datapath_8bit;

architecture structural of CipherCore_Datapath_8bit is

    constant ZEROES_WHITE          : std_logic_vector(128 - 1 downto 0):= x"93bdcae8d9e0f72bacef364fabe89454";
    
    constant NULL_PT_PAD_WHITE_A   : std_logic_vector(G_DBLK_SIZE - 1 downto 0):= "1010" & x"f8e9dbac4768569";
	constant NULL_PT_PAD_WHITE_B   : std_logic_vector(G_DBLK_SIZE - 1 downto 0):= "0010" & x"f8e9dbac4768569";
	
	constant ZEROES_AND_ONE_WHITE_A  : std_logic_vector(128 - 1 downto 0):= x"3bd78209467dbcae1278ebdcae74856" & "1101";
	constant ZEROES_AND_ONE_WHITE_B  : std_logic_vector(128 - 1 downto 0):= x"3bd78209467dbcae1278ebdcae74856" & "1100";
	
	constant IV_WHITE_A              : std_logic_vector(63 downto 0):=x"F667CB6914349bde"; -- IV constant for ASCON-128
	constant IV_WHITE_B              : std_logic_vector(63 downto 0):=x"7627C76F14349bde"; -- IV constant for ASCON-128
	--constant IV                    : std_logic_vector(63 downto 0):=x"80400C0600000000"; -- IV constant for ASCON-128

    type byte_array is array(0 to 15) of std_logic_vector(7 downto 0);
    type byte_signal_array is array(0 to 15) of std_logic;
    type tag_array is array(0 to 15) of std_logic_vector(7 downto 0);
	
    signal next_bdi_reg, bdi_reg : byte_array;
	signal next_bdi_rega, bdi_rega : byte_array;
	signal next_bdi_regb, bdi_regb : byte_array;
	
	
	signal bdi_reg_en : byte_signal_array;
    signal tag_word : tag_array;
	signal tag_worda, tag_wordb  : tag_array;
	
	
	signal next_bank0_rega, bank0_rega, bdi_data_reg_topa : std_logic_vector(63 downto 0);
	signal next_bank0_regb, bank0_regb, bdi_data_reg_topb : std_logic_vector(63 downto 0);
	
	
	signal bdi_last_ct_adjusta : std_logic_vector(63 downto 0);
	signal bdi_last_ct_adjustb : std_logic_vector(63 downto 0);
	
	
	signal bdi_data_rega, bdi_data_regb : std_logic_vector(127 downto 0);
	signal next_bank_rega, bank1_rega, bank2_rega : std_logic_vector(127 downto 0);
	signal next_bank_regb, bank1_regb, bank2_regb : std_logic_vector(127 downto 0);
		
	signal x0_in, x1_in, x2_in, x3_in, x4_in : std_logic_vector(63 downto 0);
	signal x0_ina, x1_ina, x2_ina, x3_ina, x4_ina : std_logic_vector(63 downto 0);
	signal x0_inb, x1_inb, x2_inb, x3_inb, x4_inb : std_logic_vector(63 downto 0);
	
	signal x0_out, x1_out, x2_out, x3_out, x4_out : std_logic_vector(63 downto 0);
	
	signal key_reg, mod_key : std_logic_vector(G_KEY_SIZE - 1 downto 0);
 	signal key_rega, mod_keya : std_logic_vector(G_KEY_SIZE - 1 downto 0);
 	signal key_regb, mod_keyb : std_logic_vector(G_KEY_SIZE - 1 downto 0);
 	
 	
 	signal next_bdo_rega, bdo_rega, next_bdoa : std_logic_vector(G_DBLK_SIZE - 1 downto 0);
 	signal next_bdo_regb, bdo_regb, next_bdob : std_logic_vector(G_DBLK_SIZE - 1 downto 0);

 	signal bank0_op1, bank0_op2 : std_logic_vector(G_DBLK_SIZE - 1 downto 0);
	signal op1, op2 : std_logic_vector(128 - 1 downto 0);
	signal bank0_op1a, bank0_op2a : std_logic_vector(G_DBLK_SIZE - 1 downto 0);
	signal op1a, op2a : std_logic_vector(128 - 1 downto 0);
	signal bank0_op1b, bank0_op2b : std_logic_vector(G_DBLK_SIZE - 1 downto 0);
	signal op1b, op2b : std_logic_vector(128 - 1 downto 0);
	
	signal full_tag : std_logic_vector(127 downto 0);
	signal full_taga : std_logic_vector(127 downto 0);
	signal full_tagb : std_logic_vector(127 downto 0);
	
	signal full_tag_cmpa, full_tag_cmpb : std_logic_vector(127 downto 0);
	
	signal tag_byte, tag_bytea, tag_byteb : std_logic_vector(7 downto 0);
	signal pad_rega, pad_regb, mask_reg : std_logic_vector(63 downto 0);

	signal x0_outa, x1_outa, x2_outa, x3_outa, x4_outa : std_logic_vector(63 downto 0);
	signal x0_outb, x1_outb, x2_outb, x3_outb, x4_outb : std_logic_vector(63 downto 0);

    -- Added by Behnaz ----------------------------------------------------------------------------
    --=============================================================================================
    signal ra, rb           : std_logic_vector(63 downto 0);  
    signal c1a_in, c1a_out  : std_logic_vector(63 downto 0);
    signal c2a_in, c2a_out  : std_logic_vector(63 downto 0);
    signal c1b_in, c1b_out  : std_logic_vector(63 downto 0);
    signal c2b_in, c2b_out  : std_logic_vector(63 downto 0);
    signal d1a_in, d1a_out  : std_logic_vector(63 downto 0);
    signal d2a_in, d2a_out  : std_logic_vector(63 downto 0);
    signal d1b_in, d1b_out  : std_logic_vector(63 downto 0);
    signal d2b_in, d2b_out  : std_logic_vector(63 downto 0);
    --=============================================================================================

	begin

			
-- load key & npub
-- requires 16 byte load of key and npub (shorter lengths not permitted)

	sync_process: process(clk)
	begin	
		if rising_edge(clk) then
			if (en_key = '1') then	
				key_rega <= key_rega(G_KEY_SIZE - 8 - 1 downto 0) & keya; -- left shift load
				key_regb <= key_regb(G_KEY_SIZE - 8 - 1 downto 0) & keyb; -- left shift load
			end if;
			if (clr_bdi = '1') then
				pad_rega <= x"A0495bdce83abe78";
				pad_regb <= x"20495bdce83abe78";
				mask_reg <= (others => '1');
			end if;
			if (en_bdi = '1') then
				pad_rega <= x"a5" & pad_rega(63 downto 8);
				pad_regb <= x"a5" & pad_regb(63 downto 8);
				mask_reg <= x"00" & mask_reg(63 downto 8);
			end if;
		end if;
	end process;
				
-- bank0 registers

    bdiRegs:
	for i in 0 to 15 generate
	
	    next_bdi_rega(i) <= (others => '0') when (clr_bdi = '1') else bdia;
		next_bdi_regb(i) <= (others => '0') when (clr_bdi = '1') else bdib;
		
        bdia_regs: entity work.reg_n(behavioral)
        generic map(N => 8)
        port map(
             clk => clk,
             en => bdi_reg_en(i),
             d => next_bdi_rega(i),
             q => bdi_rega(i)
		  );

        bdib_regs: entity work.reg_n(behavioral)
        generic map(N => 8)
        port map(
             clk => clk,
             en => bdi_reg_en(i),
             d => next_bdi_regb(i),
             q => bdi_regb(i)
		  );

    end generate;

    bdi_reg_en(0) <= '1' when ((ld_ctr = "0000" and en_bdi = '1') or clr_bdi = '1') else '0';
    bdi_reg_en(1) <= '1' when ((ld_ctr = "0001" and en_bdi = '1') or clr_bdi = '1') else '0';
    bdi_reg_en(2) <= '1' when ((ld_ctr = "0010" and en_bdi = '1') or clr_bdi = '1') else '0';
    bdi_reg_en(3) <= '1' when ((ld_ctr = "0011" and en_bdi = '1') or clr_bdi = '1') else '0';
    bdi_reg_en(4) <= '1' when ((ld_ctr = "0100" and en_bdi = '1') or clr_bdi = '1') else '0';
    bdi_reg_en(5) <= '1' when ((ld_ctr = "0101" and en_bdi = '1') or clr_bdi = '1') else '0';
    bdi_reg_en(6) <= '1' when ((ld_ctr = "0110" and en_bdi = '1') or clr_bdi = '1') else '0';
    bdi_reg_en(7) <= '1' when ((ld_ctr = "0111" and en_bdi = '1') or clr_bdi = '1') else '0';
    bdi_reg_en(8) <= '1' when ((ld_ctr = "1000" and en_bdi = '1') or clr_bdi = '1') else '0';
    bdi_reg_en(9) <= '1' when ((ld_ctr = "1001" and en_bdi = '1') or clr_bdi = '1') else '0';
    bdi_reg_en(10) <= '1' when ((ld_ctr = "1010" and en_bdi = '1') or clr_bdi = '1') else '0';
    bdi_reg_en(11) <= '1' when ((ld_ctr = "1011" and en_bdi = '1') or clr_bdi = '1') else '0';
    bdi_reg_en(12) <= '1' when ((ld_ctr = "1100" and en_bdi = '1') or clr_bdi = '1') else '0';
    bdi_reg_en(13) <= '1' when ((ld_ctr = "1101" and en_bdi = '1') or clr_bdi = '1') else '0';
    bdi_reg_en(14) <= '1' when ((ld_ctr = "1110" and en_bdi = '1') or clr_bdi = '1') else '0';
    bdi_reg_en(15) <= '1' when ((ld_ctr = "1111" and en_bdi = '1') or clr_bdi = '1') else '0';

	bdi_data_rega <= bdi_rega(0) & bdi_rega(1) & bdi_rega(2) & bdi_rega(3) & 
	                 bdi_rega(4) & bdi_rega(5) & bdi_rega(6) & bdi_rega(7) &
				     bdi_rega(8) & bdi_rega(9) & bdi_rega(10) & bdi_rega(11) &
				     bdi_rega(12) & bdi_rega(13) & bdi_rega(14) & bdi_rega(15);
	
	bdi_data_regb <= bdi_regb(0) & bdi_regb(1) & bdi_regb(2) & bdi_regb(3) & 
	                 bdi_regb(4) & bdi_regb(5) & bdi_regb(6) & bdi_regb(7) &
				     bdi_regb(8) & bdi_regb(9) & bdi_regb(10) & bdi_regb(11) &
				     bdi_regb(12) & bdi_regb(13) & bdi_regb(14) & bdi_regb(15);

	bdi_data_reg_topa <= bdi_data_rega(127 downto 64) xor pad_rega;
	bdi_data_reg_topb <= bdi_data_regb(127 downto 64) xor pad_regb; 
	
	bdi_last_ct_adjusta <= bdi_data_reg_topa xor (x0_outa and mask_reg); 					
    bdi_last_ct_adjustb <= bdi_data_reg_topb xor (x0_outb and mask_reg); -- but both shares get masked!
    
	-- bank0a

	with bank0_op1_sel select
		bank0_op1a  <= bdi_data_reg_topa when "00",
		               bdi_last_ct_adjusta when "01", -- right shift
					   NULL_PT_PAD_WHITE_A when "10",
					   ZEROES_WHITE(G_DBLK_SIZE - 1 downto 0) when "11",
                       (others => '0') when others;

    with bank0_op2_sel select
		bank0_op2a  <= x0_outa when "00", -- from perm
                       IV_WHITE_A when "01",
					   NULL_PT_PAD_WHITE_A when "10",
					   ZEROES_WHITE(G_DBLK_SIZE - 1 downto 0) when "11",
                       (others => '0') when others;

        next_bank0_rega <= bank0_op1a xor bank0_op2a;
						 
   	    bank0a_regs: entity work.reg_n(behavioral)
        generic map(N => 64)
        port map(
             clk => clk,
             en => bank0_en,
             d => next_bank0_rega,
             q => bank0_rega
		  );
					   

	-- bank0b

	with bank0_op1_sel select
		bank0_op1b  <= bdi_data_reg_topb when "00",
		               bdi_last_ct_adjustb when "01", -- right shift
					   NULL_PT_PAD_WHITE_B  when "10",
					   ZEROES_WHITE(G_DBLK_SIZE - 1 downto 0) when "11",
                       (others => '0') when others;

    with bank0_op2_sel select
		bank0_op2b  <= x0_outb when "00", -- from perm
                       IV_WHITE_B when "01",
					   NULL_PT_PAD_WHITE_B when "10",
					   ZEROES_WHITE(G_DBLK_SIZE - 1 downto 0) when "11",
                       (others => '0') when others;

        next_bank0_regb <= bank0_op1b xor bank0_op2b;
						 
   	    bank0b_regs: entity work.reg_n(behavioral)
        generic map(N => 64)
        port map(
             clk => clk,
             en => bank0_en,
             d => next_bank0_regb,
             q => bank0_regb
		  );
					   
-- bank1 and 2 selectors (a bus)

    with op1_sel select
		op1a <= x1_outa & x2_outa when "00",
		        x3_outa & x4_outa when "01",
			    (others => '0')       when "10",
			    (others => '0')       when "11",
			    (others => '0') when others;
					   
    with op2_sel select
		op2a <= mod_keya when "00",
		        bdi_data_rega when "01",
			    ZEROES_AND_ONE_WHITE_A when "10",
			    ZEROES_WHITE when "11",
			    (others => '0') when others;

	mod_keya <= key_rega when (key_sel = '0') else key_rega(G_KEY_SIZE - 1 downto 1) & (key_rega(0) xor '1');
    next_bank_rega <= op1a xor op2a;	

-- bank1 and 2 selectors (b bus)

    with op1_sel select
		op1b <= x1_outb & x2_outb when "00",
		        x3_outb & x4_outb when "01",
			    (others => '0')       when "10",
			    (others => '0')       when "11",
			    (others => '0') when others;
					   
    with op2_sel select
		op2b <= mod_keyb when "00",
		        bdi_data_regb when "01",
			    ZEROES_AND_ONE_WHITE_B when "10",
			    ZEROES_WHITE when "11",
			    (others => '0') when others;

	mod_keyb <= key_regb;-- when (key_sel = '0') else key_regb(G_KEY_SIZE - 1 downto 1) & (key_reg(0) xor '1'); -- only one share gets xor
    next_bank_regb <= op1b xor op2b;	

-- bank1a registers

	bank1a_regs: entity work.reg_n(behavioral)
        generic map(N => 128)
        port map(
             clk => clk,
             en => bank1_en,
             d => next_bank_rega,
             q => bank1_rega
		  );

-- bank1b registers

	bank1b_regs: entity work.reg_n(behavioral)
        generic map(N => 128)
        port map(
             clk => clk,
             en => bank1_en,
             d => next_bank_regb,
             q => bank1_regb
		  );

-- bank2a registers

	bank2a_regs: entity work.reg_n(behavioral)
        generic map(N => 128)
        port map(
             clk => clk,
             en => bank2_en,
             d => next_bank_rega,
             q => bank2_rega
		  );

-- bank2b registers

	bank2b_regs: entity work.reg_n(behavioral)
        generic map(N => 128)
        port map(
             clk => clk,
             en => bank2_en,
             d => next_bank_regb,
             q => bank2_regb
		  );

-- permutator
-- set up inputs

   x0_ina <= bank0_rega;
   x1_ina <= bank1_rega(127 downto 64);
   x2_ina <= bank1_rega(63 downto 0);
   x3_ina <= bank2_rega(127 downto 64);
   x4_ina <= bank2_rega(63 downto 0);
   
   x0_inb <= bank0_regb;
   x1_inb <= bank1_regb(127 downto 64);
   x2_inb <= bank1_regb(63 downto 0);
   x3_inb <= bank2_regb(127 downto 64);
   x4_inb <= bank2_regb(63 downto 0);

   
   perminst: entity work.permutation_TI(structural)
   port map(
		clk => clk,
		rst => perm_reset,
		perm_start => perm_start,
		done => perm_done, 
		in0a => x0_ina,
		in1a => x1_ina,
		in2a => x2_ina,
		in3a => x3_ina,
		in4a => x4_ina,
		in0b => x0_inb,
		in1b => x1_inb,
		in2b => x2_inb,
		in3b => x3_inb,
		in4b => x4_inb,
		m    => m,
		out0a => x0_outa,
		out1a => x1_outa,
		out2a => x2_outa,
		out3a => x3_outa,
		out4a => x4_outa,
		out0b => x0_outb,
		out1b => x1_outb,
		out2b => x2_outb,
		out3b => x3_outb,
		out4b => x4_outb,
		rcin => rc
		);
		
-- test section

      --x0_out <= x0_outa xor x0_outb;
      --x1_out <= x1_outa xor x1_outb;
      --x2_out <= x2_outa xor x2_outb;
      --x3_out <= x3_outa xor x3_outb;
      --x4_out <= x4_outa xor x4_outb;
		
-- write PT or CT result

    next_bdoa <= next_bank0_rega when (decrypt = '0') else bdi_data_rega(127 downto 64) xor x0_outa;
    next_bdob <= next_bank0_regb when (decrypt = '0') else bdi_data_regb(127 downto 64) xor x0_outb;
    
    next_bdo_rega <= next_bdoa when (ld_bdo = '1') else
               	    bdo_rega(G_DBLK_SIZE - 8 - 1 downto 0) & bdo_rega(G_DBLK_SIZE - 1 downto G_DBLK_SIZE - 8); -- rotate left to dump to bdo
    next_bdo_regb <= next_bdob when (ld_bdo = '1') else
               	    bdo_regb(G_DBLK_SIZE - 8 - 1 downto 0) & bdo_regb(G_DBLK_SIZE - 1 downto G_DBLK_SIZE - 8); -- rotate left to dump to bdo

    bdoa_rg: entity work.reg_n(behavioral)
    generic map(N=> G_DBLK_SIZE) -- 64
    port map(
        clk => clk,
        en => en_bdo,
        d => next_bdo_rega,
        q => bdo_rega
    );
		
    bdob_rg: entity work.reg_n(behavioral)
    generic map(N=> G_DBLK_SIZE) -- 64
    port map(
        clk => clk,
        en => en_bdo,
        d => next_bdo_regb,
        q => bdo_regb
    );
    
    
    --- Added by Behnaz ---------------------------------------------------------------------------
    --=============================================================================================
    raReg: entity work.reg_n(behavioral) -- Register random share for 64-MSB of the Tag
    generic map(N => 64)
    Port map(
        clk     => clk,
        en      => raReg_en,
        d       => m(63 downto 0),
        q       => ra
    );
    
    rbReg: entity work.reg_n(behavioral) -- Register random share for 64-LSB of the Tag
    generic map(N => 64)
    Port map(
        clk     => clk,
        en      => rbReg_en,
        d       => m(63 downto 0),
        q       => rb
    );
    
    c1a_in      <= full_taga(127 downto 64) xor bdi_data_rega(127 downto 64);
    c1aReg: entity work.reg_n(behavioral) 
    generic map(N => 64)
    Port map(
        clk     => clk,
        en      => c1a_en,
        d       => c1a_in,
        q       => c1a_out
    );
    
    c2a_in      <= full_tagb(127 downto 64) xor bdi_data_regb(127 downto 64);       
    c2aReg: entity work.reg_n(behavioral)
    generic map(N => 64)
    Port map(
        clk     => clk,
        en      => c2a_en,
        d       => c2a_in,
        q       => c2a_out
    );
    
    c1b_in      <= full_taga(63 downto 0) xor bdi_data_rega(63 downto 0);
    c1bReg: entity work.reg_n(behavioral)
    generic map(N => 64)
    Port map(
        clk     => clk,
        en      => c1b_en,
        d       => c1b_in,
        q       => c1b_out
    );
      
    c2b_in      <= full_tagb(63 downto 0) xor bdi_data_regb(63 downto 0);
    c2bReg: entity work.reg_n(behavioral)
    generic map(N => 64)
    Port map(
        clk     => clk,
        en      => c2b_en,
        d       => c2b_in,
        q       => c2b_out
    );

    d1a_in      <= c1a_out xor c2a_out xor ra;
    d1aReg: entity work.reg_n(behavioral)
    generic map(N => 64)
    Port map(
        clk     => clk,
        en      => d1a_en,
        d       => d1a_in,
        q       => d1a_out
    );
    
    d2a_in      <=  d1a_out xor ra;
    d2aReg: entity work.reg_n(behavioral)
    generic map(N => 64)
    Port map(
        clk     => clk,
        en      => d2a_en,
        d       => d2a_in,
        q       => d2a_out
    );
    
    d1b_in      <= c1b_out xor c2b_out xor rb;
    d1bReg: entity work.reg_n(behavioral)
    generic map(N => 64)
    Port map(
        clk     => clk,
        en      => d1b_en,
        d       => d1b_in,
        q       => d1b_out
    ); 
    
    d2b_in      <= d1b_out xor rb;
    d2bReg: entity work.reg_n(behavioral)
    generic map(N => 64)
    Port map(
        clk     => clk,
        en      => d2b_en,
        d       => d2b_in,
        q       => d2b_out
    ); 
    --=============================================================================================

-- write tag

   full_taga <= bank2_rega;
   full_tagb <= bank2_regb; 
 
   tagWrda:  
   for i in 0 to 15 generate
		tag_worda(i) <= full_taga(8*i+7 downto 8*i);
   end generate;
   
   with ld_ctr select
		tag_bytea <= tag_worda(15) when x"0",
                     tag_worda(14) when x"1",
                     tag_worda(13) when x"2",
                     tag_worda(12) when x"3",
                     tag_worda(11) when x"4",
                     tag_worda(10) when x"5",
                     tag_worda(9) when x"6",
                     tag_worda(8) when x"7",
                     tag_worda(7) when x"8",
                     tag_worda(6) when x"9",
                     tag_worda(5) when x"A",
                     tag_worda(4) when x"B",
                     tag_worda(3) when x"C",
                     tag_worda(2) when x"D",
                     tag_worda(1) when x"E",
                     tag_worda(0) when x"F",
                     (others => '0') when others;

   tagWrdb:  
   for i in 0 to 15 generate
		tag_wordb(i) <= full_tagb(8*i+7 downto 8*i);
   end generate;
   
   with ld_ctr select
		tag_byteb <= tag_wordb(15) when x"0",
                     tag_wordb(14) when x"1",
                     tag_wordb(13) when x"2",
                     tag_wordb(12) when x"3",
                     tag_wordb(11) when x"4",
                     tag_wordb(10) when x"5",
                     tag_wordb(9) when x"6",
                     tag_wordb(8) when x"7",
                     tag_wordb(7) when x"8",
                     tag_wordb(6) when x"9",
                     tag_wordb(5) when x"A",
                     tag_wordb(4) when x"B",
                     tag_wordb(3) when x"C",
                     tag_wordb(2) when x"D",
                     tag_wordb(1) when x"E",
                     tag_wordb(0) when x"F",
                     (others => '0') when others;

	bdoa <= tag_bytea when (sel_tag = '1') else bdo_rega(G_DBLK_SIZE - 1 downto G_DBLK_SIZE - 8);
	bdob <= tag_byteb when (sel_tag = '1') else bdo_regb(G_DBLK_SIZE - 1 downto G_DBLK_SIZE - 8);

	-- remove before t-test!
    -- test new tag comparison for protected versions
	--full_tag_cmpa <= full_taga xor bdi_data_rega;
	--full_tag_cmpb <= full_tagb xor bdi_data_regb;
	--msg_auth_valid <= '1' when (full_tag_cmpa = full_tag_cmpb) else '0'; -- exp tag
--	msg_auth_valid <= '1'; -- only for t-test
	
	--msg_auth_valid <= '1' when (full_tag = bdi_data_reg) else '0'; -- exp tag
	
	-- Added by Behnaz ---------------------------------------------------------
    --==========================================================================
    msg_auth <= '1' when ((d2a_out = 0) and (d2b_out = 0)) else '0';
    --==========================================================================
	 
end architecture structural;

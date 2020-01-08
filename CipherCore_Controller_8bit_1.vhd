-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
--! @file       CipherCore_Controller_8bit.vhd v1.1
--! @author     William Diehl 
--! @brief      Controller for ASCON128 in LW interface with PW=SW=8
--! @version    03-28-2018     
-------------------------------------------------------------------------------

library IEEE;
use IEEE.STD_LOGIC_1164.ALL;
use IEEE.STD_LOGIC_UNSIGNED.ALL;
use ieee.numeric_std.all;

entity CipherCore_Controller_8bit is
    port (
	 clk : std_logic;
	 rst : std_logic;
	 
	 bdi_ready : out std_logic;
	 bdi_valid : in std_logic;
	 bdo_ready : in std_logic;
	 bdo_valid : out std_logic;
	 key_update : in std_logic;
	 key_valid  : in std_logic;
	 key_ready  : out std_logic;
	 bdi_eoi    : in std_logic;
	 bdi_eot    : in std_logic;
    bdi_type   : in std_logic_vector(3 downto 0);
    end_of_block : out std_logic;
	 decrypt    : in std_logic;
	 
	 msg_auth	: out std_logic;
     ld_ctr_out : out std_logic_vector(3 downto 0);

	sel_tag             : out  std_logic;
   en_key              : out  std_logic;
    clr_bdi             : out  std_logic;
    en_bdi              : out  std_logic;
    en_bdo              : out  std_logic;
    ld_bdo	    	    : out  std_logic;
    msg_auth_ready      : in std_logic;
	
	 decrypt_reg_out    : out std_logic;
	 decrypt_last       : out std_logic;
    rc					: out std_logic_vector(7 downto 0);
	perm_start          : out std_logic;
	perm_done           : in std_logic;
	bank0_op1_sel           : out  std_logic_vector(1 downto 0);
	bank0_op2_sel           : out std_logic_vector(1 downto 0);
	op1_sel           : out std_logic_vector(1 downto 0);
	op2_sel           : out std_logic_vector(1 downto 0);
	bank0_en            : out std_logic;
	bank1_en            : out std_logic;
	bank2_en            : out std_logic;
	key_sel               : out std_logic;
	perm_reset          : out std_logic
	 --state_debug		   : out std_logic_vector(7 downto 0) -- profiler

     );
end CipherCore_Controller_8bit;

architecture behavioral of CipherCore_Controller_8bit is

    constant KEY_BYTES : integer := 16; -- 128 bit key
    constant NPUB_BYTES : integer := 16; -- 128 bit npub
    constant EXP_TAG_BYTES : integer := 16; -- 128 bit expected tag
    constant TAG_BYTES : integer := 16; -- 128 bit tag
    constant BDI_BYTES : integer := 8; -- 64 bit AD, M, C
	 constant AD_TYPE : integer:= 1; -- HDR_AD

    type state_type is (S_RESET, S_CHECK_KEY, S_LOAD_KEY, S_LOAD_NPUB, S_LOCK_INIT, S_START_INIT, S_PREP_LOAD,
                        S_NO_AD_OR_PT, S_FINISH_INT1, S_FINISH_INT2, S_LOAD_AD, S_PREP_AD, S_START_AD,
						      S_FINISH_AD, S_WAIT_AD1, S_WAIT_AD2, S_LOAD_PT, S_PREP_PT, S_START_PT, S_RESULT_OUT, S_FINISH_PT, 
						      S_PREP_FINAL, S_START_FINAL, S_LOAD_EXP_TAG, S_WAIT_TAG, S_TAG, S_START_FULL_AD, S_WAIT_PT_FULL	
                   );

    signal current_state, next_state : state_type;
	
signal clr_ld_ctr : std_logic;
signal en_ld_ctr : std_logic;
signal set_wr_ctr : std_logic;

signal set_no_AD_flag, no_AD_flag, reset_no_AD_flag : std_logic;
signal set_no_PT_flag, no_PT_flag, reset_no_PT_flag : std_logic;
signal set_last_AD_flag : std_logic;
signal last_AD_flag : std_logic;
signal reset_last_AD_flag : std_logic;
signal set_last_PT_flag : std_logic;
signal last_PT_flag : std_logic;
signal reset_last_PT_flag : std_logic;
signal last_AD_full_flag, set_last_AD_full_flag, reset_last_AD_full_flag : std_logic;
signal last_PT_full_flag, set_last_PT_full_flag, reset_last_PT_full_flag : std_logic;

signal ld_ctr : std_logic_vector(3 downto 0):=(others => '0');
signal wr_ctr : std_logic_vector(3 downto 0):=(others => '0');
signal decrypt_reg : std_logic:='0';
signal en_decrypt_reg : std_logic;
--signal state_debug : std_logic_vector(7 downto 0); -- profiler

begin

ld_ctr_out <= ld_ctr;
decrypt_reg_out <= decrypt_reg;

sync_process: process(clk)
begin

if (rising_edge(clk)) then
	if (rst = '1') then
	    current_state <= S_RESET; -- idle state
		
	else
	   current_state <= next_state;
	   
	  if (clr_ld_ctr = '1') then
		    ld_ctr <= (others => '0');
	  end if;
      if (en_ld_ctr = '1') then
		    ld_ctr <= std_logic_vector(unsigned(ld_ctr) + 1);
      end if;
      if (set_wr_ctr = '1') then
			 wr_ctr <= ld_ctr;
      end if;
      if (set_no_AD_flag = '1') then
          no_AD_flag <= '1';
      end if;
      if (set_no_PT_flag = '1') then
          no_PT_flag <= '1';
      end if;
      if (reset_no_AD_flag = '1') then
          no_AD_flag <= '0';
      end if;
      if (reset_no_PT_flag = '1') then
          no_PT_flag <= '0';
      end if;
      if (set_last_AD_flag = '1') then
          last_AD_flag <= '1';
      end if;
      if (reset_last_AD_flag = '1') then
          last_AD_flag <= '0';
      end if;
      if (set_last_PT_flag = '1') then
          last_PT_flag <= '1';
      end if;
      if (reset_last_PT_flag = '1') then
          last_PT_flag <= '0';
      end if;
      if (set_last_AD_full_flag = '1') then
          last_AD_full_flag <= '1';
      end if;
      if (reset_last_AD_full_flag = '1') then
          last_AD_full_flag <= '0';
      end if;
      if (set_last_PT_full_flag = '1') then
          last_PT_full_flag <= '1';
      end if;
      if (reset_last_PT_full_flag = '1') then
          last_PT_full_flag <= '0';
      end if;

	  if (en_decrypt_reg = '1') then
		 	 decrypt_reg <= decrypt;
		end if;
	end if;
	  
end if;

end process;

cipher_process: process(current_state, bdi_valid, bdo_ready, key_update, key_valid, 
                        ld_ctr, wr_ctr, bdi_eot, bdi_eoi, bdi_type, msg_auth_ready, decrypt_reg,
						      no_AD_flag, no_PT_flag, perm_done, last_AD_full_flag, last_PT_full_flag)
begin
	 -- defaults
bdi_ready <= '0';
key_ready <= '0';
bdo_valid <= '0';
end_of_block <= '0';

en_key <= '0';
clr_bdi <= '0';
en_bdi <= '0';
en_bdo <= '0';
ld_bdo <= '0';
clr_ld_ctr <= '0';
en_ld_ctr <= '0';
set_wr_ctr <= '0';
msg_auth <= '0';
sel_tag <= '0';
en_decrypt_reg <= '0';
decrypt_last <= '0';

reset_last_AD_flag <= '0';
set_last_AD_flag <= '0';
reset_last_PT_flag <= '0';
set_last_PT_flag <= '0';
reset_no_AD_flag <= '0';
set_no_AD_flag <= '0';
reset_no_PT_flag <= '0';
set_no_PT_flag <= '0';
reset_last_AD_full_flag <= '0';
set_last_AD_full_flag <= '0';
set_last_PT_full_flag <= '0';
reset_last_PT_full_flag <= '0';

perm_start <= '0';
rc <= x"F0";
bank0_en <= '0';
bank1_en <= '0';
bank2_en <= '0';
bank0_op1_sel <= "00";
bank0_op2_sel <= "00";
op1_sel <= "00";
op2_sel <= "00";
key_sel <= '0';
perm_reset <= '0';

--state_debug <= x"00"; -- profiler default

case current_state is
		 		 
        when S_RESET => 
          clr_bdi <= '1';
			 clr_ld_ctr <= '1';
			 reset_last_AD_flag <= '1';
			 reset_last_PT_flag <= '1';
			 reset_no_AD_flag <= '1';
			 reset_no_PT_flag <= '1';
			 reset_last_AD_full_flag <= '1';
			 reset_last_PT_full_flag <= '1';
			 perm_reset <= '1';
			 next_state <= S_CHECK_KEY;	
    
	when S_CHECK_KEY => 

	     if (key_update = '1') then
		     if (key_valid = '1') then
		         next_state <= S_LOAD_KEY;
             else 
                 next_state <= S_CHECK_KEY;
             end if;
         else 
		     if (bdi_valid = '1') then
                   next_state <= S_LOAD_NPUB;
		     else
                   next_state <= S_CHECK_KEY;
             end if;
	     end if;	

		 --state_debug <= x"01"; -- profiler default

	when S_LOAD_KEY => 

        if (key_valid = '1') then
			key_ready <= '1';
			en_key <= '1';
            if (ld_ctr = KEY_BYTES - 1) then
				clr_ld_ctr <= '1';
                next_state <= S_LOAD_NPUB;
            else
                en_ld_ctr <= '1';
                next_state <= S_LOAD_KEY;
            end if;
        else
            next_state <= S_LOAD_KEY;
        end if;

		 --state_debug <= x"02"; -- profiler default

	when S_LOAD_NPUB => 
 
        if (bdi_valid = '1') then
		      en_bdi <= '1';
            bdi_ready <= '1';
            if (ld_ctr = NPUB_BYTES - 1) then
			     en_decrypt_reg <= '1';
		        clr_ld_ctr <= '1';
				  --load bank 0
				  bank0_op1_sel <= "11"; -- 0
				  bank0_op2_sel <= "01"; -- IV
				  bank0_en <= '1';
				  -- load bank 1
				  op1_sel <= "10"; -- 0
				  op2_sel <= "00"; -- K
				  bank1_en <= '1';
				  if (bdi_eoi = '1') then -- no AD or PT
					 set_no_AD_flag <= '1';
					 set_no_PT_flag <= '1';
				  end if;
                next_state <= S_LOCK_INIT;
			else
			    en_ld_ctr <= '1';
			    next_state <= S_LOAD_NPUB;
			end if;
		else
		    next_state <= S_LOAD_NPUB;
	    end if;

    --state_debug <= x"04"; -- profiler default

   when S_LOCK_INIT => 	
	
	   -- load bank 2
		op1_sel <= "10";
		op2_sel <= "01";
		bank2_en <= '1'; -- N
		clr_bdi <= '1';
		next_state <= S_START_INIT;
		
   when S_START_INIT => 
   
		perm_start <= '1';
		if (no_AD_flag = '1' and no_PT_flag = '1') then
			next_state <= S_NO_AD_OR_PT;
		else
		    next_state <= S_PREP_LOAD;
		end if;
				
	when S_PREP_LOAD => 

		if (bdi_valid = '1') then
			if (bdi_type /= AD_TYPE) then
				set_no_AD_flag <= '1';
			end if;
			next_state <= S_FINISH_INT1; 
		else
			next_state <= S_PREP_LOAD;
		end if;
		
	when S_NO_AD_OR_PT => 
	
		if (perm_done = '1') then
			bank0_op1_sel <= "10";
			bank0_op2_sel <= "00";
			bank0_en <= '1';
     	   op1_sel <= "01";
         op2_sel <= "00";
		   key_sel <= '1';
		   bank2_en <= '1';
   		next_state <= S_PREP_FINAL;
		else
			next_state <= S_NO_AD_OR_PT;
		end if;
		
	when S_FINISH_INT1 =>
	
		if (perm_done = '1') then
		   bank0_op1_sel <= "11";
		   bank0_op2_sel <= "00";
		   bank0_en <= '1';		   
		   op1_sel <= "00";
		   op2_sel <= "11";
		   bank1_en <= '1';
		   next_state <= S_FINISH_INT2;
		 else
		   next_state <= S_FINISH_INT1;
		 end if;
		 
	when S_FINISH_INT2 => 
     	op1_sel <= "01";
      op2_sel <= "00";
		bank2_en <= '1';
		if (no_AD_flag = '1') then
			key_sel <= '1';
			next_state <= S_LOAD_PT; 
		else
			next_state <= S_LOAD_AD;
		end if;

    when S_LOAD_AD =>

		if (bdi_valid = '1') then
			bdi_ready <= '1';
			en_bdi <= '1';
			if (ld_ctr = BDI_BYTES - 1 or bdi_eot = '1') then
				clr_ld_ctr <= '1';
				if (bdi_eot = '1') then
					set_last_AD_flag <= '1';
					if (ld_ctr = BDI_BYTES - 1) then
						set_last_AD_full_flag <= '1';
					end if;
					if (bdi_eoi = '1') then
						set_no_PT_flag <= '1';
					end if;
				end if;
				next_state <= S_PREP_AD;
			else
				en_ld_ctr <= '1';
				next_state <= S_LOAD_AD;
			end if;
		else
			next_state <= S_LOAD_AD;
		end if;
		
	when S_PREP_AD =>
	
		bank0_op1_sel <= "00";
		bank0_op1_sel <= "00";
		bank0_en <= '1';
		clr_bdi <= '1'; 
		next_state <= S_START_AD;
		
	when S_START_AD => 
	
		rc <= x"96";
		perm_start <= '1';
		if (last_AD_flag = '1' and last_AD_full_flag = '0') then
			next_state <= S_FINISH_AD;
		else
			next_state <= S_WAIT_AD1; 
		end if;
		
	when S_WAIT_AD1 => 
	
		if (perm_done = '1') then
			op1_sel <= "00";
			op2_sel <= "11";
			bank1_en <= '1';
			next_state <= S_WAIT_AD2;
		else
			next_state <= S_WAIT_AD1;
		end if;
		
	when S_WAIT_AD2 => 
	
		  op1_sel <= "01";
		  op2_sel <= "11";
		  bank2_en <= '1';
		  if (last_AD_full_flag = '1') then
		      bank0_op1_sel <= "10";
				bank0_op2_sel <= "00";
				bank0_en <= '1';
				next_state <= S_START_FULL_AD;
		  else
				next_state <= S_LOAD_AD;
		  end if;
		  
   when S_START_FULL_AD =>
	
		  rc <= x"96";
		  perm_start <= '1';
		  next_state <= S_FINISH_AD;
		
	when S_FINISH_AD => 
		if (perm_done = '1') then
		   -- load bank 2 with end of AD delimiter
			op1_sel <= "01";
			op2_sel <= "10";
			bank2_en <= '1';
			if (no_PT_flag = '1') then
				bank0_op1_sel <= "10";
				bank0_op2_sel <= "00";
				next_state <= S_PREP_FINAL;
			else
				bank0_op1_sel <= "11";
				bank0_op2_sel <= "00";
				next_state <= S_LOAD_PT; 
			end if;
			bank0_en <= '1';
		else
			next_state <= S_FINISH_AD;
		end if;
		
	when S_LOAD_PT => 

		if (bdi_valid = '1') then
			bdi_ready <= '1';
			en_bdi <= '1';
			if (ld_ctr = BDI_BYTES - 1 or bdi_eot = '1') then
				
				clr_ld_ctr <= '1';
				set_wr_ctr <= '1';
				if (bdi_eot = '1') then
					set_last_PT_flag <= '1';
					if (ld_ctr = BDI_BYTES - 1) then
						set_last_PT_full_flag <= '1';
					end if;
				end if;
				op1_sel <= "00";
				op2_sel <= "11";
				bank1_en <= '1';
				next_state <= S_PREP_PT;
			else
				en_ld_ctr <= '1';
				next_state <= S_LOAD_PT;
			end if;
		else
			next_state <= S_LOAD_PT;
		end if;
	
    when S_PREP_PT => 

		if (decrypt_reg = '1') then
			if (last_PT_flag = '1' and last_PT_full_flag = '0') then
			   bank0_op1_sel <= "01";
				bank0_op2_sel <= "11";
				next_state <= S_RESULT_OUT;
			else
				bank0_op1_sel <= "00";
				bank0_op2_sel <= "11";
				next_state <= S_START_PT;
			end if;
      else			
			bank0_op1_sel <= "00";
			bank0_op2_sel <= "00";
			if (last_PT_flag = '1' and last_PT_full_flag = '0') then
				next_state <= S_RESULT_OUT;
			else
				next_state <= S_START_PT;
			end if;
		end if;
		
		bank0_en <= '1';
		ld_bdo <= '1';
		en_bdo <= '1';
		clr_bdi <= '1';
	
	when S_START_PT => 
	
		rc <= x"96";
		perm_start <= '1';
		next_state <= S_RESULT_OUT;
		
	when S_RESULT_OUT => 
	
		if (bdo_ready = '1') then
			bdo_valid <= '1';
			en_bdo <= '1';
			if (ld_ctr = wr_ctr) then
				end_of_block <= '1';
				clr_ld_ctr <= '1';
				if (last_PT_flag = '1') then
				   if (last_PT_full_flag = '1') then
						next_state <= S_WAIT_PT_FULL;
					else
						next_state <= S_PREP_FINAL;
					end if;
				else
					next_state <= S_FINISH_PT;
				end if;
			else
				en_ld_ctr <= '1';
				next_state <= S_RESULT_OUT;
			end if;
		else
			next_state <= S_RESULT_OUT;
		end if;
		
	when S_WAIT_PT_FULL => 

			if (perm_done = '1') then
				bank0_op1_sel <= "10";
				bank0_op2_sel <= "00";
				bank0_en <= '1';
				op1_sel <= "01";
				op2_sel <= "11";
				bank2_en <= '1';
				next_state <= S_PREP_FINAL;
			else
				next_state <= S_WAIT_PT_FULL;
			end if;
				
	when S_FINISH_PT => 
		  if (perm_done = '1') then
				op1_sel <= "01";
				op2_sel <= "11";
				bank2_en <= '1';
				next_state <= S_LOAD_PT;
			else
				next_state <= S_FINISH_PT;
			end if;
		
	when S_PREP_FINAL =>
	   op1_sel <= "00";
		op2_sel <= "00";
		bank1_en <= '1'; 
		next_state <= S_START_FINAL;
		
	when S_START_FINAL => 
	
		perm_start <= '1';
		if (decrypt_reg = '1') then
			next_state <= S_LOAD_EXP_TAG;
		else
			next_state <= S_WAIT_TAG;
		end if;
		
	when S_LOAD_EXP_TAG => 
		
        if (bdi_valid = '1') then
		      en_bdi <= '1';
            bdi_ready <= '1';
            if (ld_ctr = TAG_BYTES - 1) then
		        clr_ld_ctr <= '1';
				  next_state <= S_WAIT_TAG;
			   else
			     en_ld_ctr <= '1';
			     next_state <= S_LOAD_EXP_TAG;
			   end if;
		  else
		    next_state <= S_LOAD_EXP_TAG;
	     end if;
					
   when S_WAIT_TAG => 

		if (perm_done = '1') then
			op1_sel <= "01";
			op2_sel <= "00";
			bank2_en <= '1';
			next_state <= S_TAG;
		else
			next_state <= S_WAIT_TAG;
		end if;
		
	when S_TAG => 
	
		if (decrypt_reg = '1') then
			if (msg_auth_ready = '1') then
				msg_auth <= '1';
				next_state <= S_RESET;
			else
				next_state <= S_TAG;
			end if;
		else
			if (bdo_ready = '1') then
				bdo_valid <= '1';
				en_bdo <= '1';
				sel_tag <= '1';
				if (ld_ctr = TAG_BYTES - 1) then
					end_of_block <= '1';
					next_state <= S_RESET;
				else
					en_ld_ctr <= '1';
					next_state <= S_TAG;
				end if;
			else
				next_state <= S_TAG;
			end if;
		end if;
		
    when others => 
	
	end case;
	end process;

	
end behavioral; 

-- and_3TI_c

library ieee;
use ieee.std_logic_1164.ALL;

entity and_3TI_c is
    generic(N:integer:=32);
    port (

	xa, xb, ya, yb, m  : in  std_logic_vector(N-1 downto 0);
	o		: out std_logic_vector(N-1 downto 0)
	);

end entity and_3TI_c;

architecture dataflow of and_3TI_c is

attribute keep_hierarchy : string;
attribute keep_hierarchy of dataflow: architecture is "true";

begin

	o <= (xa and ya) xor (xb and ya) xor (xa and yb) xor m;

end dataflow;

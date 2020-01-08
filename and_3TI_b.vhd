-- and_3TI_b

library ieee;
use ieee.std_logic_1164.ALL;

entity and_3TI_b is
    generic(N : integer:=32);
    port (

	xa, xb, ya, yb, m  : in  std_logic_vector(N-1 downto 0);
	o		: out std_logic_vector(N-1 downto 0)
	);

end entity and_3TI_b;

architecture dataflow of and_3TI_b is

attribute keep_hierarchy : string;
attribute keep_hierarchy of dataflow: architecture is "true";

begin

	o <= (xb and ya) xor (xa and yb) xor (xa and ya) xor (xa and m) xor (m and ya);

end dataflow;

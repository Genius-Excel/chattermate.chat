-- Enable the vector extension
CREATE EXTENSION IF NOT EXISTS vector;



-- Set up vector similarity search functions
CREATE OR REPLACE FUNCTION vector_similarity(vector1 vector, vector2 vector)
RETURNS float
AS $$
BEGIN
    RETURN 1 - (vector1 <=> vector2);
END;
$$ LANGUAGE plpgsql; 
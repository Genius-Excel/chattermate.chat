"""
ChatterMate - Test Knowledge Search Byagent
Copyright (C) 2024 ChatterMate

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>
"""

import pytest
from unittest.mock import patch, MagicMock
from app.tools.knowledge_search_byagent import KnowledgeSearchByAgent
from app.models.knowledge import Knowledge, SourceType
from uuid import uuid4
from agno.knowledge.agent import AgentKnowledge
from agno.vectordb.pgvector import PgVector, SearchType
import os

@pytest.fixture
def mock_db():
    """Create a mock database session"""
    db = MagicMock()
    return db

@pytest.fixture
def mock_knowledge():
    """Create a mock knowledge entry"""
    knowledge_id = uuid4()
    org_id = uuid4()
    return Knowledge(
        id=knowledge_id,
        organization_id=org_id,
        source="test_document.pdf",
        source_type=SourceType.FILE,
        table_name="test_table",
        schema="test_schema"
    )

@pytest.fixture
def mock_vector_db():
    """Create a mock vector database"""
    vector_db = MagicMock(spec=PgVector)
    vector_db.table_name = "test_table"
    vector_db.schema = "test_schema"
    vector_db.search_type = SearchType.hybrid
    # Mock the search method to avoid OpenAI API key requirement
    vector_db.search.return_value = []
    return vector_db

@pytest.fixture
def mock_agent_knowledge(mock_vector_db):
    """Create a mock agent knowledge"""
    agent_knowledge = MagicMock(spec=AgentKnowledge)
    # Mock the search method to return an empty list by default
    agent_knowledge.search.return_value = []
    # Set the vector_db attribute
    agent_knowledge.vector_db = mock_vector_db
    return agent_knowledge

@pytest.fixture
def mock_ai_config():
    """Create a mock AI config"""
    ai_config = MagicMock()
    ai_config.encrypted_api_key = "test-key"
    return ai_config

@pytest.fixture
def knowledge_search_tool(mock_db, mock_knowledge, mock_vector_db, mock_agent_knowledge, mock_ai_config):
    """Create a KnowledgeSearchByAgent instance with mocked dependencies"""
    agent_id = str(uuid4())
    org_id = uuid4()
    
    # Set up environment variables first
    os.environ['OPENAI_API_KEY'] = 'test-key'
    
    with patch('app.tools.knowledge_search_byagent.get_db') as mock_get_db, \
         patch('app.tools.knowledge_search_byagent.PgVector') as mock_pg_vector, \
         patch('app.tools.knowledge_search_byagent.AgentKnowledge') as mock_agent_knowledge_class, \
         patch('app.tools.knowledge_search_byagent.KnowledgeRepository') as mock_knowledge_repo_class, \
         patch('app.tools.knowledge_search_byagent.AIConfigRepository') as mock_ai_config_repo_class, \
         patch('app.tools.knowledge_search_byagent.decrypt_api_key') as mock_decrypt_api_key:
        
        # Configure mocks
        mock_get_db.return_value.__next__.return_value = mock_db
        mock_pg_vector.return_value = mock_vector_db
        mock_agent_knowledge_class.return_value = mock_agent_knowledge
        
        # Create a mock for KnowledgeRepository
        mock_knowledge_repo = MagicMock()
        mock_knowledge_repo_class.return_value = mock_knowledge_repo
        mock_knowledge_repo.get_by_agent.return_value = [mock_knowledge]
        
        # Configure AI config mocks
        mock_ai_config_repo = MagicMock()
        mock_ai_config_repo_class.return_value = mock_ai_config_repo
        mock_ai_config_repo.get_active_config.return_value = mock_ai_config
        mock_decrypt_api_key.return_value = "test-key"
        
        # Create tool instance
        tool = KnowledgeSearchByAgent(agent_id=agent_id, org_id=org_id)
        
        # For test access
        tool._mock_knowledge_repo = mock_knowledge_repo
        tool.agent_knowledge = mock_agent_knowledge  # Set the agent_knowledge directly
        
        return tool

def test_search_knowledge_base_success(knowledge_search_tool):
    """Test successful knowledge base search"""
    # Setup
    query = "test query"
    mock_doc = MagicMock()
    mock_doc.content = "Test content"
    mock_doc.name = "test_document.pdf"
    mock_doc.score = 0.95
    knowledge_search_tool.agent_knowledge.search.return_value = [mock_doc]
    
    # Execute
    result = knowledge_search_tool.search_knowledge_base(query)
    
    # Assert
    assert "[FILE - test_document.pdf] Test content" in result
    knowledge_search_tool.agent_knowledge.search.assert_called_once_with(
        query=query,
        num_documents=5,
        filters={"agent_id": [knowledge_search_tool.agent_id]}
    )

def test_search_knowledge_base_no_sources(knowledge_search_tool):
    """Test knowledge base search with no knowledge sources"""
    # Setup
    knowledge_search_tool._mock_knowledge_repo.get_by_agent.return_value = []
    
    # Execute
    result = knowledge_search_tool.search_knowledge_base("test query")
    
    # Assert
    assert result == "No knowledge sources available for this agent."

def test_search_knowledge_base_no_results(knowledge_search_tool):
    """Test knowledge base search with no search results"""
    # Setup
    knowledge_search_tool.agent_knowledge.search.return_value = []
    
    # Execute
    result = knowledge_search_tool.search_knowledge_base("test query")
    
    # Assert
    assert result == "No relevant information found in the knowledge base."

def test_search_knowledge_base_multiple_results(knowledge_search_tool):
    """Test knowledge base search with multiple results"""
    # Setup
    query = "test query"
    
    # Create mock documents with string values for name
    mock_docs = []
    for i, (name, content, score) in enumerate([
        ("doc1.pdf", "Content 1", 0.95),
        ("doc2.pdf", "Content 2", 0.85),
        ("doc3.pdf", "Content 3", 0.75),
        ("doc4.pdf", "Content 4", 0.65)
    ]):
        doc = MagicMock()
        doc.name = name  # Set name as a string
        doc.content = content
        doc.score = score
        mock_docs.append(doc)
    
    knowledge_search_tool.agent_knowledge.search.return_value = mock_docs
    
    # Set up mock knowledge sources to match document names
    mock_knowledge_sources = [
        Knowledge(
            id=uuid4(),
            organization_id=uuid4(),
            source="doc1.pdf",
            source_type=SourceType.FILE,
            table_name="test_table",
            schema="test_schema"
        ),
        Knowledge(
            id=uuid4(),
            organization_id=uuid4(),
            source="doc2.pdf",
            source_type=SourceType.FILE,
            table_name="test_table",
            schema="test_schema"
        ),
        Knowledge(
            id=uuid4(),
            organization_id=uuid4(),
            source="doc3.pdf",
            source_type=SourceType.FILE,
            table_name="test_table",
            schema="test_schema"
        ),
        Knowledge(
            id=uuid4(),
            organization_id=uuid4(),
            source="doc4.pdf",
            source_type=SourceType.FILE,
            table_name="test_table",
            schema="test_schema"
        )
    ]
    knowledge_search_tool.knowledge_repo.get_by_agent.return_value = mock_knowledge_sources

    # Execute
    result = knowledge_search_tool.search_knowledge_base(query)

    # Assert
    assert "[FILE - doc1.pdf] Content 1" in result
    assert "[FILE - doc2.pdf] Content 2" in result
    assert "[FILE - doc3.pdf] Content 3" in result
    assert "[FILE - doc4.pdf] Content 4" not in result  # Should be excluded as we only take top 3

def test_search_knowledge_base_empty_content(knowledge_search_tool):
    """Test knowledge base search with empty content in results"""
    # Setup
    
    # Create mock documents with string values for name
    mock_docs = []
    for name, content, score in [
        ("doc1.pdf", "", 0.95),  # Empty content
        ("doc2.pdf", None, 0.85),  # None content
        ("doc3.pdf", "Valid content", 0.75)
    ]:
        doc = MagicMock()
        doc.name = name  # Set name as a string
        doc.content = content
        doc.score = score
        mock_docs.append(doc)
    
    knowledge_search_tool.agent_knowledge.search.return_value = mock_docs
    
    # Set up mock knowledge sources to match document names
    mock_knowledge_sources = [
        Knowledge(
            id=uuid4(),
            organization_id=uuid4(),
            source="doc1.pdf",
            source_type=SourceType.FILE,
            table_name="test_table",
            schema="test_schema"
        ),
        Knowledge(
            id=uuid4(),
            organization_id=uuid4(),
            source="doc2.pdf",
            source_type=SourceType.FILE,
            table_name="test_table",
            schema="test_schema"
        ),
        Knowledge(
            id=uuid4(),
            organization_id=uuid4(),
            source="doc3.pdf",
            source_type=SourceType.FILE,
            table_name="test_table",
            schema="test_schema"
        )
    ]
    knowledge_search_tool.knowledge_repo.get_by_agent.return_value = mock_knowledge_sources

    # Execute
    result = knowledge_search_tool.search_knowledge_base("test query")

    # Assert
    assert "[FILE - doc3.pdf] Valid content" in result
    assert "doc1.pdf" not in result  # Empty content should be filtered out
    assert "doc2.pdf" not in result  # None content should be filtered out 

def test_search_knowledge_base_error(knowledge_search_tool):
    """Test knowledge base search error handling"""
    # Setup
    knowledge_search_tool.agent_knowledge.search.side_effect = Exception("Search failed")
    
    # Execute
    result = knowledge_search_tool.search_knowledge_base("test query")
    
    # Assert
    assert result == "Error searching knowledge base."
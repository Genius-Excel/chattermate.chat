"""
ChatterMate - Enhanced Website Knowledge Base
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

from typing import Any, Dict, Iterator, List, Optional
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from agno.document import Document
from agno.knowledge.agent import AgentKnowledge
from agno.embedder import Embedder
from app.core.logger import get_logger
from app.core.config import settings
from pydantic import model_validator

from app.knowledge.enhanced_website_reader import EnhancedWebsiteReader

# Initialize logger for this module
logger = get_logger(__name__)


class EnhancedWebsiteKnowledgeBase(AgentKnowledge):
    """Enhanced knowledge base for websites with more robust content extraction"""
    
    urls: List[str] = []
    reader: Optional[EnhancedWebsiteReader] = None

    # Reader parameters - using settings from config
    max_depth: int = settings.KB_MAX_DEPTH
    max_links: int = settings.KB_MAX_LINKS 
    min_content_length: int = settings.KB_MIN_CONTENT_LENGTH
    timeout: int = settings.KB_TIMEOUT
    max_retries: int = settings.KB_MAX_RETRIES
    max_workers: int = settings.KB_MAX_WORKERS
    batch_size: int = settings.KB_BATCH_SIZE
    optimize_on: Optional[int] = settings.KB_OPTIMIZE_ON

    @model_validator(mode="after")
    def set_reader(self) -> "EnhancedWebsiteKnowledgeBase":
        """Set the reader if not provided"""
        if self.reader is None:
            logger.info(f"Initializing EnhancedWebsiteReader with max_depth={self.max_depth}, max_links={self.max_links}, max_workers={self.max_workers}")
            self.reader = EnhancedWebsiteReader(
                max_depth=self.max_depth,
                max_links=self.max_links,
                min_content_length=self.min_content_length,
                timeout=self.timeout,
                max_retries=self.max_retries,
                max_workers=self.max_workers
            )
        return self

    def _process_url(self, url: str) -> List[Document]:
        """Process a single URL and return its documents"""
        try:
            url_start_time = time.time()
            logger.info(f"Crawling URL: {url}")
            
            # Get documents from the reader without embedding
            documents = self.reader.read(url=url)
            
            # Now embed documents in parallel if possible
            if self.vector_db and hasattr(self.vector_db, 'embedder') and documents:
                unembedded_docs = [doc for doc in documents if doc.embedding is None]
                if unembedded_docs:
                    # Use ThreadPoolExecutor for parallel embedding
                    with ThreadPoolExecutor(max_workers=min(len(unembedded_docs), self.max_workers)) as executor:
                        # Create a list of future tasks
                        futures = []
                        for doc in unembedded_docs:
                            futures.append(executor.submit(self._embed_document, doc, self.vector_db.embedder))
                        
                        # Wait for all embeddings to complete
                        for future in as_completed(futures):
                            try:
                                future.result()  # Get any exceptions that occurred
                            except Exception as e:
                                logger.error(f"Error during parallel embedding: {str(e)}")
            
            url_end_time = time.time()
            url_duration = url_end_time - url_start_time
            
            # Log document details
            page_count = len(set(doc.meta_data.get('url', '') for doc in documents))
            logger.info(f"Completed {url} - Extracted {len(documents)} documents from {page_count} pages ({url_duration:.2f}s)")
            
            return documents
        except Exception as e:
            logger.error(f"Error reading URL {url}: {str(e)}")
            return []
    
    def _embed_document(self, document: Document, embedder: Embedder) -> None:
        """Embed a single document (for parallel processing)"""
        try:
            if document.embedding is None:
                document.embed(embedder=embedder)
        except Exception as e:
            logger.error(f"Error embedding document '{document.id}': {str(e)}")
            raise

    def _process_document_batch(self, documents: List[Document], filters: Optional[Dict[str, Any]] = None) -> None:
        """Process a batch of documents by inserting them into the vector database"""
        if not documents or not self.vector_db:
            return

        try:
            batch_start_time = time.time()
            
            # Use the most efficient upsert method available
            self.vector_db.upsert(documents=documents, filters=filters)
            
            batch_end_time = time.time()
            batch_duration = batch_end_time - batch_start_time
        except Exception as e:
            logger.error(f"Error processing document batch: {str(e)}")

    @property
    def document_lists(self) -> Iterator[List[Document]]:
        """
        Iterate over urls and yield lists of documents.
        Each object yielded by the iterator is a list of documents.

        Returns:
            Iterator[List[Document]]: Iterator yielding list of documents
        """
        if self.reader is not None:
            total_start_time = time.time()
            logger.info(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Starting to process {len(self.urls)} URLs")
            
            # Process URLs in parallel using ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Submit all URLs for processing
                future_to_url = {executor.submit(self._process_url, url): url for url in self.urls}
                
                # Process completed futures as they finish
                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        documents = future.result()
                        if documents:
                            yield documents
                    except Exception as e:
                        logger.error(f"Error processing URL {url}: {str(e)}")
                        yield []
            
            total_end_time = time.time()
            total_duration = total_end_time - total_start_time
            logger.info(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Completed processing all {len(self.urls)} URLs (Total time: {total_duration:.2f}s)")

    def load(
        self,
        recreate: bool = False,
        upsert: bool = True,
        skip_existing: bool = True,
        filters: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Load the website contents to the vector db with parallel processing and batch insertion
        
        Args:
            recreate (bool, optional): Whether to recreate the collection. Defaults to False.
            upsert (bool, optional): Whether to upsert documents. Defaults to True.
            skip_existing (bool, optional): Whether to skip existing documents. Defaults to True.
            filters (Optional[Dict[str, Any]], optional): Filters to apply to the documents. Defaults to None.
        """
        total_start_time = time.time()
        
        if self.vector_db is None:
            logger.warning("No vector db provided")
            return

        if self.reader is None:
            logger.warning("No reader provided")
            return

        if recreate:
            self.vector_db.drop()
            self.vector_db.create()
        elif not self.vector_db.exists():
            self.vector_db.create()

        logger.info(f"Starting knowledge base loading - {len(self.urls)} URLs")

        # Check if URLs exist in vector db
        urls_to_read = self.urls.copy()
        if not recreate and skip_existing:
            try:
                urls_to_read = [url for url in self.urls if not self.vector_db.name_exists(name=url)]
                skipped = len(self.urls) - len(urls_to_read)
                if skipped > 0:
                    logger.info(f"Skipping {skipped} already loaded URLs")
            except Exception as e:
                logger.error(f"Error checking existing URLs: {str(e)}")
                urls_to_read = self.urls.copy()

        # Process URLs in parallel with batched vector DB insertion
        total_documents = 0
        
        # Keep track of crawling vs upsert timing
        crawl_start_time = time.time()

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all URLs for processing
            future_to_url = {executor.submit(self._process_url, url): url for url in urls_to_read}
            all_documents = []
            
            # Process completed futures as they finish
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    documents = future.result()
                    total_documents += len(documents)
                    
                    # Collect documents for batch processing
                    all_documents.extend(documents)
                        
                except Exception as e:
                    logger.error(f"Error processing URL {url}: {str(e)}")
        
        crawl_end_time = time.time()
        crawl_duration = crawl_end_time - crawl_start_time
        logger.info(f"Crawling completed - {len(urls_to_read)} URLs, {total_documents} documents, {crawl_duration:.2f}s")
        
        # Make sure all documents are embedded before upsert (final check for any that were missed)
        unembedded_count = sum(1 for doc in all_documents if doc.embedding is None)
        if unembedded_count > 0 and self.vector_db and hasattr(self.vector_db, 'embedder'):
            logger.info(f"Embedding remaining {unembedded_count} documents")
            unembedded_docs = [doc for doc in all_documents if doc.embedding is None]
            
            # Use ThreadPoolExecutor for parallel embedding with a high worker count for best parallelism
            with ThreadPoolExecutor(max_workers=min(32, len(unembedded_docs))) as executor:
                # Create a list of future tasks
                futures = []
                for doc in unembedded_docs:
                    futures.append(executor.submit(self._embed_document, doc, self.vector_db.embedder))
                
                # Wait for all embeddings to complete
                for future in as_completed(futures):
                    try:
                        future.result()  # Get any exceptions that occurred
                    except Exception as e:
                        logger.error(f"Error during embedding: {str(e)}")
        
        # Process all documents in optimally sized batches
        if all_documents and upsert:
            logger.info(f"Inserting {len(all_documents)} documents into vector database")
            
            # Process in larger batches for better DB performance
            for i in range(0, len(all_documents), self.batch_size):
                batch = all_documents[i:i + self.batch_size]
                self._process_document_batch(batch, filters)
            
        # Optimize vector db if needed
        if self.optimize_on is not None and total_documents > self.optimize_on and hasattr(self.vector_db, 'optimize'):
            logger.info("Optimizing vector database...")
            try:
                self.vector_db.optimize()
            except Exception as e:
                logger.error(f"Vector DB optimization failed: {str(e)}")

        total_end_time = time.time()
        total_duration = total_end_time - total_start_time
        logger.info(f"Completed loading {total_documents} documents from {len(urls_to_read)} URLs (Total time: {total_duration:.2f}s)") 